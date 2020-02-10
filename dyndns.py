import argparse
import glob
import logging
import os
import smtplib
import socket
import ssl
import subprocess
import tempfile
import time
from collections import namedtuple
from stat import S_ISREG, ST_CTIME, ST_MODE

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

import dyndns_config

log_file_name = os.path.splitext(os.path.basename(__file__))[0]
logging.basicConfig(
    level=dyndns_config.loglevel,
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.FileHandler("{0}.log".format(log_file_name)),
        logging.StreamHandler()
    ]
)


def update(host="NOTHING", ipv4=None, ipv6=None, use_source=False, user=None):
    result = 'host: {}, IPv4: {}, IPv6: {}\n'.format(
        host, is_valid_ipv4_address(ipv4), is_valid_ipv6_address(ipv6))
    # result += '{}/n {}/n'.format(dir(req), req.document_root())
    if not validate_user(host, user):
        return "User {} not authorized".format(user)

    if use_source:
        ip = use_source
        if ':' in ip:
            ipv6 = ip
        else:
            ipv4 = ip
    ips = dict()
    if is_valid_ipv4_address(ipv4):
        ips[ipv4] = 'A'

    if is_valid_ipv6_address(ipv6):
        ips[ipv6] = 'AAAA'

    # queue_path = get_queue_path(os.path.dirname(req.filename))
    queue_path = get_queue_path("")
    for ip in ips.keys():
        try:
            if dns_is_changed(host, ip):
                result += write_queue_file(queue_path, host, ip, ips[ip])
                logging.info("DNS update queued. msg: {}".format(result))
            else:
                result += "No update needed, ip {} already set".format(ip)
        except socket.gaierror:
            result += "Can't resolve {}".format(host)
            break
        except TypeError:
            result += "Can't resolve {}, wrong format. ".format(host)

    return result


def validate_user(host, user):
    """
    host: fqdn of the record that will be set
    user: typically user@dyn.domain.com

    Return True, if
     - User Auth disabled dyndns_config.disable_user_authorization = True
     - user has full rights, user in dyndns_config.full_access_user
     - user is allowed for this domain, user in dyndns_config.domain_access_user and
       domain part matches host and user
     - host matches the user, "test.dyndns.example.com" == "test@dyndns.example.com"

    """
    if hasattr(dyndns_config, 'disable_user_authorization') and dyndns_config.disable_user_authorization:
        logging.warning("User authorization disabled. Any user even anonymous is allowed!")
        return True
    if not user:
        logging.error('User is invalid. User: {}'.format(user))
        return False
    if hasattr(dyndns_config, 'full_access_user') and user in dyndns_config.full_access_user:
        logging.info("User {} is allowed to change any record.".format(user))
        return True
    if hasattr(dyndns_config, 'domain_access_user') and user in dyndns_config.domain_access_user:
        if user.endswith(domain_from_fqdn(host)):
            logging.info('User {} is allowed to change any record in {}'.format(user, domain_from_fqdn(host)))
            return True
        else:
            logging.warning('User {} not authorized for domain {}'.format(user, domain_from_fqdn(host)))
            return False
    if user.replace('@', '.').lower() == host.rstrip('.'):
        logging.debug('User {} allowed to update {}.'.format(user, host))
        return True
    else:
        logging.warning("User {} doesn't match {}, access denied.".format(user, host))
        return False


def dns_is_changed(host, ip):
    for l in socket.getaddrinfo(host, 0):
        if l[4][0] == ip:
            return False
    return True


def is_resolvable(host):
    try:
        socket.getaddrinfo(host, 0)
        return True
    except socket.gaierror:
        logging.debug("Can't resolve {}".format(host))
        return False
    except TypeError:
        logging.debug("Can't resolve {}, wrong format. ".format(host))
        return False


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    except TypeError:
        return False

    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    except TypeError:
        return False
    return True


def write_queue_file(path, host, ip, type):
    temp_name = next(tempfile._get_candidate_names()) + ".update"
    file_name = os.path.join(path, temp_name)

    try:
        with open(file_name, 'w') as queue_file:
            queue_file.write('{},{},{}'.format(host, ip, type))
    except IOError:
        return "Can't access {}, create directory and make sure permissions are set correct.".format(file_name)
    return "Update for {} queued".format(host)


def get_queue_path(script_path):
    if dyndns_config.queue_dir.startswith('/'):
        logging.debug('Absolute path to queue given.')
        return dyndns_config.queue_dir
    else:
        return os.path.join(script_path, dyndns_config.queue_dir)


def ipv6_explode_str(ip):
    ts = ip.split(':')
    i6 = ['0000'] * 8
    space_count = 8 - len(ts) + 1
    i = 0
    while not ts[i] == '':
        i6[i] = ts[i].zfill(4)
        i += 1
    ii = i + space_count
    i += 1
    for _ in range(9 - space_count - i):
        i6[ii] = ts[i].zfill(4)
        ii += 1
        i += 1
    return ':'.join(i6)


def __change_plesk_dns(cmd, domain, host, ip, type):
    hostname = host.split('.', 1)[0]
    cmd_switch = "{} {}".format(cmd, domain)
    type_switch = "{} {}".format(type.lower(), hostname)
    cmd_line = '/usr/sbin/plesk bin dns --{} -{} -ip {}'.format(cmd_switch, type_switch, ip).split()
    logging.debug('CMD: {}'.format(' '.join(cmd_line)))
    exit = subprocess.call(cmd_line)
    if exit == 0:
        logging.info("cmd {} for entry {} {} {} successful".format(
            cmd, host, type, ip
        ))
    return exit


def domain_from_fqdn(fqdn):
    """
    strips of hostname from FQDN. 
    Strips also pending `.` if there
    If there is no hostpart `IndexError` will be thrown
    """
    return fqdn.rstrip('.').split('.', 1)[1]


def __update_plesk(host, ip, type):
    if not host.endswith('.'):
        host = host + '.'
    if not is_resolvable(host):
        logging.error('Host {} is not resolvable, ignore')
        return False
    domain = domain_from_fqdn(host)

    if domain not in dyndns_config.dyn_dns_domains:
        logging.error('Domain {} not allowed for dynamic updates.'.format(domain))
        return False

    lines = subprocess.check_output(
        '/usr/sbin/plesk bin dns --info {}'.format(domain),
        stderr=subprocess.STDOUT,
        shell=True
    ).decode().split('\n')
    dns_record = namedtuple('dns_record', ["host", "type", "ip"])
    dns_records = []
    for line in lines:
        try:
            (p_host, p_type, p_ip) = line.split()
            dns_records.append(dns_record(host=p_host, type=p_type, ip=p_ip))
            logging.debug('Found following record {}.'.format(line))
        except ValueError:
            # logging.debug('ignore line: {}'.format(line))
            pass

    new_record = dns_record(host=host, type=type, ip=ip)
    if new_record in dns_records:
        logging.info('DNS uptodate.')
        return True
    else:
        logging.info('DNS update reqired')
        result = 1000
        for record in dns_records:
            if record.host == host and record.type == type:
                result = __change_plesk_dns("del", domain, host, record.ip, type)
                time.sleep(5)
            else:
                result = 0
        if result == 0:
            result = __change_plesk_dns('add', domain, host, ip, type)
        if result == 0:
            return True
        else:
            return False


def get_queued_files():
    queue_path = get_queue_path(os.path.dirname(os.path.realpath(__file__)))

    # get all entries in the directory w/ stats
    entries = glob.glob(os.path.join(queue_path, '*.update'))
    entries = ((os.stat(path), path) for path in entries)

    # leave only regular files, insert creation date
    entries = ((stat[ST_CTIME], path)
               for stat, path in entries if S_ISREG(stat[ST_MODE]))
    # NOTE: on Windows `ST_CTIME` is a creation date
    #  but on Unix it could be something else
    # NOTE: use `ST_MTIME` to sort by a modification date
    return entries


def read_queued_files(entries):
    updates = {}
    for cdate, path in sorted(entries):
        logging.debug('{}\t{}'.format(time.ctime(cdate), path))
        with open(path, 'r') as dns_update:
            try:
                (host, ip, type) = dns_update.read().split(',')
            except ValueError:
                logging.error("Can't parse content of file: {}".format(path))
                os.rename(path, path + '.error')
        logging.info('Host = {}, IP = {}, Type = {}'.format(host, ip, type))
        if type == 'A':
            if not is_valid_ipv4_address(ip):
                logging.error('IP {}, is not valid, ignore'.format(ip))
                continue
        elif type == 'AAAA':
            if not is_valid_ipv6_address(ip):
                logging.error('IP {}, is not valid, ignore'.format(ip))
                continue
        if not updates.get(host): updates[host] = {}
        updates[host][type] = ip
        if __update_plesk(host, ip, type):
            updates[host]['status'] = True
            os.remove(path)
        else:
            updates[host]['status'] = False
            os.rename(path, path + '.error')

    for fqdn in updates.keys():
        if hasattr(dyndns_config, 'smtp_enabled') and dyndns_config.smtp_enabled:
            send_email_notification(
                fqdn,
                dyndns_config.smtp_recipient,
                ipv4=updates[fqdn].get('A',    'No Update'),
                ipv6=updates[fqdn].get('AAAA', 'No Update'),
            )


class Watcher:
    DIRECTORY_TO_WATCH = get_queue_path(os.path.dirname(os.path.realpath(__file__)))

    def __init__(self):
        self.observer = Observer()
        self.timeout = -1

    def run(self):
        runtime = 0
        event_handler = Handler()
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
                runtime += 5
                if runtime > self.timeout > 0:
                    break
        except Exception as e:
            self.observer.stop()
            logging.exception("Error while watching queue dir. ERROR: {}".format(e))

        self.observer.stop()

    def set_timeout(self, seconds):
        self.timeout = seconds


class Handler(FileSystemEventHandler):

    @staticmethod
    def on_any_event(event):
        if event.is_directory:
            return None

        elif event.event_type == 'created':
            # Take any action here when a file is first created.
            logging.debug("Received created event - %s." % event.src_path)
            read_queued_files(get_queued_files())

        elif event.event_type == 'modified':
            # Taken any action here when a file is modified.
            logging.debug("Received modified event - %s." % event.src_path)


def send_email_notification(fqdn, recipient, ipv4="Not updated", ipv6="Not updated"):
    if not dyndns_config.smtp_enable:
        return
    for smtp_cfg in ('smtp_server', 'smtp_port', 'smtp_mode', 'smtp_sender'):
        if not hasattr(dyndns_config, smtp_cfg):
            logging.error("SMTP setting missing. Please provide: {}".format(smtp_cfg))
            return
    if dyndns_config.smtp_mode == 'ssl':
        # Create a secure SSL context
        context = ssl.create_default_context()
        smtp_server = smtplib.SMTP_SSL
    else:
        context = None
        smtp_server = smtplib.SMTP

    msg = """Subject: DYNDNS update: {fqdn}
    Dear Admin,

    we have updated your DNS record for {fqdn}
    new IPv4 address: {IPv4}
    new IPv6 address: {IPv6}

    Bye
      Your DYN DNS Service
    """.format(fqdn=fqdn, IPv4=ipv4, IPv6=ipv6)

    with smtp_server(dyndns_config.smtp_server, dyndns_config.smtp_port, context=context) as server:
        if hasattr(dyndns_config, 'smtp_user') and hasattr(dyndns_config, 'smtp_password'):
            server.login(dyndns_config.smtp_user, dyndns_config.smtp_password)
        server.sendmail(dyndns_config.smtp_sender, recipient, msg)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='dyndns sever - server side process')

    parser.add_argument('--timeout', action="store", default=-1, type=int,
                        help='Seconds until automatic termination. Use if you run via cron job')
    parser.add_argument('--runonce', action="store_true", default=False,
                        help='Process pending files and stop, no monitoring')
    args = parser.parse_args()

    if args.runonce:
        logging.basicConfig(level=logging.DEBUG)
        read_queued_files(get_queued_files())
    else:
        w = Watcher()
        w.set_timeout(args.timeout)
        w.run()
