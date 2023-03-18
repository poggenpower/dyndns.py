import os
import sys
import logging
import logging.handlers

VirtualEnvDirectory = 'venv'
VirtualEnv = os.path.join(os.getcwd(), VirtualEnvDirectory, 'bin', 'python')
if sys.executable != VirtualEnv: os.execl(VirtualEnv, VirtualEnv, *sys.argv)

from urllib.parse import parse_qs
import dyndns

logFormatter = logging.Formatter("%(asctime)s [%(filename)s:%(lineno)s - %(funcName)20s() ] [%(levelname)-5.5s]  %(message)s")
file_path = os.path.splitext(os.path.realpath(__file__))[0]
fileHandler = logging.handlers.TimedRotatingFileHandler("{0}.log".format(file_path), when="d", interval=1, backupCount=5 )
fileHandler.setFormatter(logFormatter)
logging.getLogger().addHandler(fileHandler)
logging.getLogger().setLevel(logging.DEBUG)


def application(environ, start_response):
    # Sorting and stringifying the environment key, value pairs
    response_body = []

    qs = parse_qs(environ['QUERY_STRING'])
    logging.debug(qs)

    update_params = dict()
    # get first element of list per qs variable 
    if qs.get('host'): update_params['host'] = qs.get('host')[0]
    if qs.get('hostname'): update_params['host'] = qs.get('hostname')[0]
    if qs.get('ipv4'): update_params['ipv4'] = qs['ipv4'][0]
    if qs.get('ipv6'): update_params['ipv6'] = qs['ipv6'][0]
    if qs.get('myip'): update_params['myip'] = qs['myip'][0]
    if qs.get('use_source', ['false'])[0].lower() == 'true':
        update_params['use_source'] = environ.get('REMOTE_ADDR')
    if environ.get('REMOTE_USER'): update_params['user'] = environ['REMOTE_USER']

    status, ip, msg = dyndns.update(**update_params)
        
    response_body.append(
        "{} {}".format(status, ip)
    )
    if not "dyndns" in qs.get('system',[]):
        response_body.append('################# Verbose Response #################')
        response_body.append(msg)

        response_body.append('################# Query String #################')
        response_body.extend(
            ['%s: %s' % (key, value) for key, value in sorted(qs.items())]
        )


    response_body = '\n'.join(response_body)
    status = '200 OK'
    response_headers = [
        ('Content-Type', 'text/plain'),
        ('Content-Length', str(len(response_body)))
    ]
    start_response(status, response_headers)
    return [response_body]
