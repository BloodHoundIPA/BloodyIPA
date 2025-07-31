#! /usr/bin/env python3
import re
import argparse, datetime, time, logging, sys
from ldap3 import Server, Connection, SIMPLE, ANONYMOUS, SASL, KERBEROS, ALL
from python_freeipa import ClientMeta
from python_freeipa import exceptions as ipa_exceptions
from requests import exceptions as requests_exceptions


from bloodyipa.ipa_object_collector import IPAobjectCollector


# disable ssl warnings
import urllib3
urllib3.disable_warnings()


class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class Collector(object):
    def __init__(self, kerberos_auth, dc, username, password, logger, verify_ssl=False, use_ldap=False, anonymous_collect=False):
        self.dc = dc
        self.base_dn = ''
        self.logger = logger
        self.use_ldap = use_ldap
        self.verify_ssl = verify_ssl
        self.anonymous_collect = anonymous_collect
        self.kerberos_auth = kerberos_auth
        if self.use_ldap:
            self.ldap_auth(username, password)
        else:
            self.api_auth(username, password)


    def api_auth(self, username, password):
        self.client = ClientMeta(self.dc, verify_ssl=self.verify_ssl)
        if self.kerberos_auth:
            try:
                self.client.login_kerberos()
            except ipa_exceptions.Unauthorized as error:
                self.logger.error("An exception occurred:", error)
                exit(0)
        else:
            try:
                self.client.login(username, password)
            except requests_exceptions.SSLError as error:
                self.logger.error(f"An exception occurred: {error}")
                self.logger.error("try '-no_verify_certificate'")
                exit(0)
            except ipa_exceptions.InvalidSessionPassword as error:
                self.logger.error(f"An exception occurred: {error}")
                exit(0)
            except requests_exceptions.ConnectionError as error:
                self.logger.error(f"An exception occurred: {error}")
                self.logger.error("Probably typo in DC name?")
                exit(0)


    def ldap_auth(self, username, password):
        server = Server(self.dc, get_info=ALL)
        Connection(server, auto_bind=True)
        self.base_dn = server.info.naming_contexts[0]
        
        if self.kerberos_auth:
            self.client = Connection(self.dc, authentication=SASL, sasl_mechanism=KERBEROS)
        elif self.anonymous_collect:
            self.client = Connection(self.dc, authentication=ANONYMOUS,)
        else:
            self.client = Connection(self.dc, user=f'uid={username},cn=users,cn=accounts,{self.base_dn}', password=password, authentication=SIMPLE,)
        self.client.bind()
        


    def run(self, timestamp=""):
        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'user', use_ladp=self.use_ldap, dn=f'cn=users,cn=accounts,{self.base_dn}')
        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'host', use_ladp=self.use_ldap, dn=f'cn=computers,cn=accounts,{self.base_dn}', filter='(fqdn=*)')
        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'service', use_ladp=self.use_ldap, dn=f'cn=services,cn=accounts,{self.base_dn}', filter='(krbprincipalname=*)')

        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'group', use_ladp=self.use_ldap, dn=f'cn=groups,cn=accounts,{self.base_dn}')
        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'hostgroup', use_ladp=self.use_ldap, dn=f'cn=hostgroups,cn=accounts,{self.base_dn}')
        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'netgroup', use_ladp=self.use_ldap, dn=f'cn=ng,cn=alt,{self.base_dn}')

        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'role', use_ladp=self.use_ldap, dn=f'cn=roles,cn=accounts,{self.base_dn}')
        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'sudorule', use_ladp=self.use_ldap, dn=f'cn=sudorules,cn=sudo,{self.base_dn}')
        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'sudocmd', use_ladp=self.use_ldap, dn=f'cn=sudocmds,cn=sudo,{self.base_dn}')
        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'sudocmdgroup', use_ladp=self.use_ldap, dn=f'cn=sudocmdgroups,cn=sudo,{self.base_dn}')

        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'hbacrule', use_ladp=self.use_ldap, dn=f'cn=hbac,{self.base_dn}')
        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'permission', use_ladp=self.use_ldap, dn=f'cn=permissions,cn=pbac,{self.base_dn}')
        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'privilege', use_ladp=self.use_ldap, dn=f'cn=privileges,cn=pbac,{self.base_dn}')

        IPAobjectCollector(self.client, self.dc, timestamp, self.logger, 'trust', use_ladp=self.use_ldap, dn=f'cn=trusts,{self.base_dn}', filter='(objectclass=ipaNTTrustedDomain)')


def main():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stream = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    stream.setFormatter(CustomFormatter())
    logger.addHandler(stream)
    anonymous_collect = False

    parser = argparse.ArgumentParser(add_help=True, description='FreeIPA python collector', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-u', '--username', action='store', help='Domain admin username')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos for auth')
    parser.add_argument('-p', '--password', action='store', help='Domain admin password')
    parser.add_argument('-dc', '--domain-controller', metavar='HOST', action='store', help='DC hostname')
    parser.add_argument('-v', action='store_true', help='Enable verbose output')
    parser.add_argument('-use_ldap', action='store_true', help='Collect objects from ldap')
    parser.add_argument('-no_verify_certificate', action='store_false', help='No verify certificate')
    args = parser.parse_args()


    if args.v is True:
        logger.setLevel(logging.DEBUG)

    if (args.kerberos is False) and args.use_ldap and (args.username is None or args.password is None) and args.domain_controller is not None:
        logger.warning('No credentials were provided. Trying to collect data anonymously...')
        anonymous_collect = True
    elif (args.kerberos is False) and (args.username is None or args.password is None or args.domain_controller is None):
        logger.error('Please specify DC, username and password or use $KRB5CCNAME')
        parser.print_help()
        exit(1)


    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S')
    collector = Collector(args.kerberos, args.domain_controller, args.username, args.password, logger, verify_ssl=args.no_verify_certificate, use_ldap=args.use_ldap, anonymous_collect=anonymous_collect)
    collector.run(timestamp=timestamp)


if __name__ == '__main__':
    main()
