import argparse
import datetime
import time
import logging
from logging import Logger
from bloodyipa.freeipa import FreeIPA
from bloodyipa.freeipa_ldap import FreeIPALDAP
from bloodyipa.freeipa_api import FreeIPAPI
from argparse import Namespace
import json
import urllib3
from bloodyipa.config import VERSION, BANNER


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
    logger.info(f'File {file_name}.json created')


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


def func_api(args: Namespace, timestamp: str, logger: Logger):
    auth_type: str
    if args.kerberos is True:
        logger.debug('Authentication: $KRB5CCNAME')
        auth_type = 'KRB5CCNAME'
    elif all((args.username, args.password, args.domain_controller)):
        logger.debug('Authentication: username/password')
        auth_type = 'password'
    else:
        logger.error('Please specify DC, username and password. Or use $KRB5CCNAME')
        exit(1)
    urllib3.disable_warnings()
    save(
        FreeIPAPI(auth_type, args.domain_controller, args.username, args.password),
        timestamp,
        logger
    )


def func_ldap(args: Namespace, timestamp: str, logger: Logger):
    auth_type: str
    if all((args.username, args.password)):
        logger.debug('Authentication: SIMPLE')
        auth_type = 'SIMPLE'
    else:
        logger.debug('Authentication: ANONYMOUS')
        auth_type = 'ANONYMOUS'
    save(
        FreeIPALDAP(
            ip=args.ip, dc=args.domain_controller, user=args.username, password=args.password, auth_type=auth_type
        ),
        timestamp,
        logger
    )


def main():
    parser = argparse.ArgumentParser(
        prog='bloodyipa',
        description='FreeIPA python collector',
        add_help=False
    )
    parser.add_argument('--version', action='store_true', help='Version')
    parser.add_argument('-v', action='store_true', help='Enable verbose output')
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='show this help message and exit')

    subparsers = parser.add_subparsers(help='Methods to collect', title='Methods to collect')

    api_parser = subparsers.add_parser('api', help='Collect with API', add_help=False)
    api_parser.add_argument('-u', '--username', action='store', help='Username')
    api_parser.add_argument('-p', '--password', action='store', help='Password')
    api_parser.add_argument('-k', '--kerberos', action='store_true', help='Use $KRB5CCNAME for auth')
    api_parser.add_argument('-dc', '--domain-controller', metavar='HOST', action='store', help='DC hostname')
    api_parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                            help='show this help message and exit')
    api_parser.set_defaults(func=func_api)

    ldap_parser = subparsers.add_parser('ldap', help='Collect with LDAP', add_help=False)
    ldap_parser.add_argument('-u', '--username', action='store', help='Username')
    ldap_parser.add_argument('-p', '--password', action='store', help='Password')
    ldap_parser.add_argument('--anonymous', action='store_true', help='Use ANONYMOUS LDAP')
    ldap_parser.add_argument('-ip', action='store', help='IP address')
    ldap_parser.add_argument('-dc', '--domain-controller', metavar='HOST', action='store', help='DC hostname')
    ldap_parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                             help='show this help message and exit')
    ldap_parser.set_defaults(func=func_ldap)

    args = parser.parse_args()

    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S')
    client: FreeIPA

    logging.basicConfig(format='%(levelname)s - %(name)s - '
                               '%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG if args.v else logging.INFO)
    logger = logging.getLogger('bloodyipa.main')

    if args.version:
        print(f'Version: {VERSION}')
        exit(0)
    print(BANNER)
    try:
        args.func(args, timestamp, logger)
    except Exception as exc:
        logger.error('\n'.join(exc.args))
        exit(1)


if __name__ == '__main__':
    main()
