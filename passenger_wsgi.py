import sys, os
ApplicationDirectory = 'dyndns' 
ApplicationName = 'dyndns' 
VirtualEnvDirectory = 'python-app-venv' 
VirtualEnv = os.path.join(os.getcwd(), VirtualEnvDirectory, 'bin', 'python') 
if sys.executable != VirtualEnv: os.execl(VirtualEnv, VirtualEnv, *sys.argv) 
sys.path.insert(0, os.path.join(os.getcwd(), ApplicationDirectory)) 
sys.path.insert(0, os.path.join(os.getcwd(), ApplicationDirectory, ApplicationName)) 
sys.path.insert(0, os.path.join(os.getcwd(), VirtualEnvDirectory, 'bin')) 
# os.chdir(os.path.join(os.getcwd(), ApplicationDirectory)) 

from urllib.parse import parse_qs
import dyndns
def application (environ, start_response):
    # Sorting and stringifying the environment key, value pairs
    response_body = [ ] 

    qs = parse_qs(environ['QUERY_STRING'])
    response_body.append('################# Query String #################')
    response_body.extend(
        ['%s: %s' % (key, value) for key, value in sorted(qs.items())]
    )

    response_body.append('################# DynDNS Response #################')
    # get first element of list per qs variable 
    host = qs.get('host')[0] if qs.get('host') else None
    ipv4 = qs['ipv4'][0] if qs.get('ipv4') else None
    ipv6 = qs['ipv6'][0] if qs.get('ipv6') else None
    if qs.get('use_source',['false'])[0].lower() == 'true':
        use_source = environ.get('REMOTE_ADDR')
    else:
        use_source = False
    response_body.append(
        dyndns.update(host=host, ipv4=ipv4, ipv6=ipv6, use_source=use_source)
    )

    response_body = '\n'.join(response_body)
    status = '200 OK'
    response_headers = [
        ('Content-Type', 'text/plain'),
        ('Content-Length', str(len(response_body)))
    ]
    start_response(status, response_headers)
    return [response_body]

