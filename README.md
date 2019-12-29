# dyndns.py

WSIG python script to update dns records via plesk.

If your webserver is managed by plesk, this script allows you to provide your own DynDNS service.

## Functionality

As the webserver user is not allowed to update the DNS settings in plesk the funktionality need to be splitted into two taks. 
1. Web Interface: Receiving update requestion via http(s) request as WSIG service and writing this request to a queue in the file system.
2. Background Job: Checking the queue and send update to plesk via `plesk cli ...` command line (unfortunately there is no rest API to that in Onyx 17.8) as root.

The script `dyndns.py` covers most of the two tasks.

## Requirements
- DNS manged by plesk 
  - subdomain for dynamic records recommended
  - dynmic DNS records must be created manually before updated by this script
- webserver running python via WSIG 
- root access to your server


### 1. Web Interface

As plesk offers WSGI support via passenger, follow mainly this description to install python3, virtualenv and passenger: https://support.plesk.com/hc/en-us/articles/115002701209-How-to-allow-installing-and-install-Django-applications-
For me it was necessary to set the `PassengerAppRoot`.
Here the additional directive for Apache.
```
PassengerAppRoot /var/www/vhosts/example.com/dyn.example.com/pyroot
PassengerEnabled On
PassengerAppType wsgi
PassengerStartupFile passenger_wsgi.py
```

You need to install the `watchdog` module in to the virtualenvironment
```
. python-app-venv/bin/activate
pip install watchdog
```

Rename `dyndns_config.py.sample` to `dyndns_config.py` and customizes to your needs. Details about the config, see below.
The `passenger_wsgi.py` is customized with the function `application` which calles the `update` function in dyndns.py with the right parameters. If you using another WSIG server, this funktion may need some customizations. 

Make sure you have created the queue directory you have specified in `dyndns_config.py`.

### 2. Background Job

Running `dyndns.py` from the cli will pick up DNS updates from the queue directory and send updates the records via plesk. This command need to be run as root, because no other user is allowed to send changes to plesk.
Without running this background job, the updates won't end up in DNS.

Make sure you run the background job with the same virtualenv then web interface.
Like this: `/var/www/vhosts/example.com/dyn.example.com/pyroot/python-app-venv/bin/python /var/www/vhosts/example.com/dyn.example.com/pyroot/dyndns.py`

```
usage: dyndns.py [-h] [--timeout TIMEOUT] [--runonce]

dyndns sever - server side process

optional arguments:
  -h, --help         show this help message and exit
  --timeout TIMEOUT  Seconds until automatic termination. Use if you run via
                     cron job
  --runonce          Process pending files and stop, no monitoring
```

There are 3 ways to run the background job to process updates. 
1. `--runonce` is mainly for testing, it will automatically switch to debug logging. It processes all queued updates and quits then.
2. `--timeout ##` Will run for `##` seconds and monitors the queue directory while running. Update will be send to plesk as they where written into the queue. Use this to run the job from cron. E.g. run it once an hour with a timeout of 3570 seconds. 
like `11  * * * * /var/www/vhosts/example.com/dyn.example.com/pyroot/python-app-venv/bin/python /var/www/vhosts/example.com/dyn.example.com/pyroot/dyndns.py`
--timeout 3570`
3. Without any parameter it runs as foreground processen and continiously processes updates. You can use this to create a servie with system ctl. Or run it with `nohup` or `screen`.

## Security

- You should protect the web interface via basic authentication, otherwise everyone who knows the URL can send updates.
- Limit the domains via `dyn_dns_domains` in the config. 
- all DNS records for the allowed domains can be updated via this script. It is strongly recommended to use a subdomain to limit impact to other services.
- the record must exist already, the script won't create new records.


## Configuration
`dyndns_config.py` contains some configuration options:
```
# make sure this file is written in proper python syntax 

# list of domains, that are allowed for updates via this script.
dyn_dns_domains = ['dyn.example.com']


# Path to the folder, that is uesed for queueing updates. Don't put other files in this directory.
# relative path to dyndns.py or absulute path, makse sure your webser can write.
queue_dir = '../queue'

# set log level. Use `logging.error` if run by cron or `logging.debug` for troubleshooting
import logging
loglevel = logging.INFO
```

## Todo
- mapping between user and allowed hostnames.
- sending email notifications if DNS update occured
