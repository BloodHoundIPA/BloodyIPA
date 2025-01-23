#! /usr/bin/env python
import argparse
import datetime
import time
import logging
from logging import Logger
import sys
from bloodyipa import FreeIPAPI, FreeIPA, FreeIPALDAP
import json

# just disable ssl warnings
import urllib3
urllib3.disable_warnings()


def write(data: list, file_name: str, logger: Logger):
    with open(f'{file_name}.json', 'w') as file:
        file.write(json.dumps({
            'data': data,
            'meta': {
                'methods': 0,
                'type': 'freeipa',
                'count': len(data),
                'version': 6
            }
        }, indent=2))
    logger.debug(f'File {file_name}.json created')


def save(client: FreeIPA, timestamp: str, logger: Logger):
    # timestamp = "20241117190147"
    write(client.collect_users(), f'{timestamp}_ipa_users', logger)
    write(client.collect_hosts(), f'{timestamp}_ipa_hosts', logger)
    write(client.collect_groups(), f'{timestamp}_ipa_groups', logger)
    write(client.collect_sudo(), f'{timestamp}_ipa_sudo', logger)
    write(client.collect_roles(), f'{timestamp}_roles', logger)
    write(client.collect_privileges(), f'{timestamp}_privileges', logger)
    write(client.collect_permissions(), f'{timestamp}_permissions', logger)
    write(client.collect_services(), f'{timestamp}_services', logger)
    write(client.collect_hbac(), f'{timestamp}_hbac', logger)


def main():
    parser = argparse.ArgumentParser(
        add_help=True, description='FreeIPA python collector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-u', '--username', action='store', help='Username')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use $KRB5CCNAME for auth')
    parser.add_argument('-p', '--password', action='store', help='Password')
    parser.add_argument('-dc', '--domain-controller', metavar='HOST', action='store', help='DC hostname')
    parser.add_argument('-ip', action='store', help='IP address')
    parser.add_argument('--api', action='store_true', help='Use api')
    parser.add_argument('--ldap', action='store_true', help='Use ldap')
    parser.add_argument('-v', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S')
    client: FreeIPA

    logging.basicConfig(format='%(levelname)s - %(name)s - '
                               '%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG if args.v else logging.INFO)
    logger = logging.getLogger('main')

    if args.api:
        auth_type: str
        if args.kerberos is True:
            logger.debug('Authentication: $KRB5CCNAME')
            auth_type = 'KRB5CCNAME'
        elif args.username is not None and args.password is not None and args.domain_controller is not None:
            logger.debug('Authentication: username/password')
            auth_type = 'password'
        else:
            logger.error('Please specify DC, username and password. Or use $KRB5CCNAME')
            exit(1)
        client = FreeIPAPI(auth_type, args.domain_controller, args.username, args.password)
    elif args.ldap:
        client = FreeIPALDAP(ip=args.ip, dc=args.domain_controller, user=args.username, password=args.password)

    save(client, timestamp, logger)


if __name__ == '__main__':
    main()
