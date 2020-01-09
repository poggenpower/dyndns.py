import os
import sys
from urllib.parse import parse_qs
import dyndns

ApplicationDirectory = 'dyndns'
ApplicationName = 'dyndns'
VirtualEnvDirectory = 'python-app-venv'
VirtualEnv = os.path.join(os.getcwd(), VirtualEnvDirectory, 'bin', 'python')
if sys.executable != VirtualEnv: os.execl(VirtualEnv, VirtualEnv, *sys.argv)
sys.path.insert(0, os.path.join(os.getcwd(), ApplicationDirectory))
sys.path.insert(0, os.path.join(os.getcwd(), ApplicationDirectory, ApplicationName))
sys.path.insert(0, os.path.join(os.getcwd(), VirtualEnvDirectory, 'bin'))


# os.chdir(os.path.join(os.getcwd(), ApplicationDirectory))


def application(environ, start_response):
    # Sorting and stringifying the environment key, value pairs
    response_body = []

    qs = parse_qs(environ['QUERY_STRING'])
    response_body.append('################# Query String #################')
    response_body.extend(
        ['%s: %s' % (key, value) for key, value in sorted(qs.items())]
    )

    response_body.append('################# DynDNS Response #################')
    update_params = dict()
    # get first element of list per qs variable 
    if qs.get('host'): update_params['host'] = qs.get('host')[0]
    if qs.get('ipv4'): update_params['ipv4'] = qs['ipv4'][0]
    if qs.get('ipv6'): update_params['ipv6'] = qs['ipv6'][0]
    if qs.get('use_source', ['false'])[0].lower() == 'true':
        update_params['use_source'] = environ.get('REMOTE_ADDR')
    if environ.get('REMOTE_USER'): update_params['user'] = environ['REMOTE_USER']
    response_body.append(
        dyndns.update(**update_params)
    )

    response_body = '\n'.join(response_body)
    status = '200 OK'
    response_headers = [
        ('Content-Type', 'text/plain'),
        ('Content-Length', str(len(response_body)))
    ]
    start_response(status, response_headers)
    return [response_body]
