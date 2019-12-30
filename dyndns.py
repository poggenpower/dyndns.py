import dyndns_config
import socket
import os
import glob
import subprocess
import tempfile
from stat import S_ISREG, ST_CTIME, ST_MODE
import time
from collections import namedtuple
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import argparse
import logging
logging.basicConfig(level=dyndns_config.loglevel)


def update(host="NOTHING", ipv4=None, ipv6=None, use_source=False):
    result = 'host: {}, IPv4: {}, IPv6: {}\n'.format(
        host, is_valid_ipv4_address(ipv4), is_valid_ipv6_address(ipv6))
    # result += '{}/n {}/n'.format(dir(req), req.document_root())
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
            else:
                result += "No update needed, ip {} already set".format(ip)
        except socket.gaierror:
            result += "Can't resolve {}".format(host)
            break
        except TypeError:
            result += "Can't resolve {}, wrong format. ".format(host)

    return result


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
        return "Can't access {}, create directory and make sure parmissions are set correct.".format(file_name)
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


def __update_plesk(host, ip, type):
    if not host.endswith('.'):
        host = host + '.'
    if not is_resolvable(host):
        logging.error('Host {} is not resolvable, ignore')
        return False
    domain = host.rstrip('.').split('.', 1)[1]

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
        if type == 'AAAA':
            if not is_valid_ipv6_address(ip):
                logging.error('IP {}, is not valid, ignore'.format(ip))
                continue
        if __update_plesk(host, ip, type):
            os.remove(path)
        else:
            os.rename(path, path + '.error')


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
                if runtime > self.timeout and self.timeout > 0:
                    break
        except Exception as e:
            self.observer.stop()
            logging.exception("Error while watching queue dir.")

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='dyndns sever - server side process')

    parser.add_argument('--timeout', action="store", default=-1, type=int, help='Seconds until automatic termination. Use if you run via cron job')
    parser.add_argument('--runonce', action="store_true", default=False, help='Process pending files and stop, no monitoring')
    args = parser.parse_args()

    if args.runonce:
        logging.basicConfig(level=logging.DEBUG)
        read_queued_files(get_queued_files())
    else:
        w = Watcher()
        w.set_timeout(args.timeout)
        w.run()
