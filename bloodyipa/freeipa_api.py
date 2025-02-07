import logging
from typing import Dict

from python_freeipa import ClientMeta
from python_freeipa import exceptions as ipa_exceptions
from requests import exceptions as requests_exceptions
from bloodyipa import FreeIPA
import base64
import datetime


class FreeIPAPI(FreeIPA):

    _username: str
    _password: str
    _dc: str
    _verify_ssl: bool
    _client: ClientMeta
    _bh_types: Dict[str, str] = {
        'user': 'IPAUser',
        'host': 'IPAHost',
        'group': 'IPAUserGroup',
        'hostgroup': 'IPAHostGroup',
        'netgroup': 'IPANetGroup',
        'service': 'IPAService',
        'role': 'IPARole',
        'privilege': 'IPAPrivilege',
        'permission': 'IPAPermission',
        'sudocmd': 'IPASudo',
        'sudocmdgroup': 'IPASudoGroup',
        'sudorule': 'IPASudoRule',
        'hbacsvc': 'IPAHBACService',
        'hbacsvcgroup': 'IPAHBACServiceGroup',
        'hbacrule': 'IPAHBACRule',
        'subid': 'IPASubId', #   TODO: add to ui
    }

    def __init__(self, auth_type: str, dc: str, username: str, password: str, verify_ssl: bool = False):
        self._username = username
        self._password = password
        self._dc = dc
        self._verify_ssl = verify_ssl
        self._client = ClientMeta(self._dc, verify_ssl=self._verify_ssl)
        self._logger = logging.getLogger('api')
        if auth_type == 'KRB5CCNAME':
            self._user_ccname_client()
        elif auth_type == 'password':
            self._user_pass_client()

    def _user_ccname_client(self):
        try:
            self._client.login_kerberos()
        except ipa_exceptions.Unauthorized as error:
            self._logger.error(f"An exception occurred: {error}")
            exit(1)

    def _user_pass_client(self):
        try:
            self._client.login(self._username, self._password)
        except ipa_exceptions.InvalidSessionPassword as error:
            self._logger.error(f"An exception occurred: {error}")
            exit(1)
        except requests_exceptions.ConnectionError as error:
            self._logger.error(f"An exception occurred: {error}")
            exit(1)

    def _collect_users(self):
        return self._client.user_find(o_sizelimit=0).get('result', [])

    def collect_hosts(self):
        return self._client.host_find(o_sizelimit=0).get('result', [])

    def _collect_usergroups(self):
        return self._client.group_find(o_sizelimit=0).get('result', [])

    def _collect_hostgroups(self):
        return self._client.hostgroup_find(o_sizelimit=0).get('result', [])

    def _collect_netgroups(self):
        return self._client.netgroup_find(o_sizelimit=0).get('result', [])

    def _collect_sudocmd(self):
        return self._client.sudocmd_find(o_sizelimit=0).get('result', [])

    def _collect_sudogroups(self):
        return self._client.sudocmdgroup_find(o_sizelimit=0).get('result', [])

    def _collect_sudorule(self):
        return self._client.sudorule_find(o_sizelimit=0).get('result', [])

    def collect_roles(self):
        return self._client.role_find(o_sizelimit=0).get('result', [])

    def collect_privileges(self):
        return self._client.privilege_find(o_sizelimit=0).get('result', [])

    def collect_permissions(self):
        return self._client.permission_find(o_sizelimit=0).get('result', [])

    def collect_services(self):
        return self._client.service_find(o_sizelimit=0).get('result', [])

    def _collect_hbacservices(self):
        return self._client.hbacsvc_find(o_sizelimit=0).get('result', [])

    def _collect_hbacservicegroups(self):
        return self._client.hbacsvcgroup_find(o_sizelimit=0).get('result', [])

    def _collect_hbacrule(self):
        return self._client.hbacrule_find(o_sizelimit=0).get('result', [])

    def _collect_ipa_objects(self, raw_data: list, object_type: str, name: str, object_id: str, highvalue_func):
        edge_rules = {
            'member': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': self._edge(other_type, object_type)
            },
            'memberuser': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': self._edge(other_type, object_type)
            },
            'memberhost': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': self._edge(other_type, object_type)
            },
            'memberservice': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': self._edge(other_type, object_type)
            },
            'memberallowcmd': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False, 'allow': True}}
            },
            'memberdenycmd': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False, 'allow': False}}
            },
            'memberof': lambda uid, other, other_type: {
                'source': {'type': object_type, 'uid': uid},
                'target': {'type': other_type, 'uid': other},
                'edge': self._edge(object_type, other_type)
            },
            'membermanager': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': {'type': 'IPAMemberManager', 'properties': {'isacl': True}}
            }
        }
        ipa_objects = []
        object_id = object_id.lower()
        for data in raw_data:
            ipa_object = dict()
            edges = []
            for key, value in data.items():
                key = key.lower()
                if key in ['krblastpwdchange', 'krbpasswordexpiration', 'krblastadminunlock', 'krblastfailedauth']:
                    ipa_object[key] = value[0]['__datetime__']
                    continue
                elif key in ['krbextradata', 'usercertificate']:
                    ipa_object[key] = base64.b64decode(value[0]['__base64__']).decode('utf-8', errors='ignore')
                    continue
                elif key.count('_'):
                    edge_rule, bh_type = key.split('_', maxsplit=1)
                    if edge_rules.get(edge_rule):
                        for other_uid in value:
                            edges.append(edge_rules[edge_rule](data[object_id][0], other_uid, self._bh_types[bh_type]))
                        continue
                if type(value) is not list:
                    value = [value]
                if len(value) > 1:
                    ipa_object[key] = list(map(
                        lambda v: str(v) if type(v) in [datetime.datetime, bytes] else v,
                        value
                    ))
                else:
                    ipa_object[key] = str(value[0]) if type(value[0]) in [datetime.datetime, bytes] else value[0]
            ipa_object['name'] = ipa_object[name.lower()]
            ipa_object['object_id'] = ipa_object[object_id.lower()]
            ipa_object['highvalue'] = False
            for edge in edges:
                if highvalue_func(edge):
                    ipa_object['highvalue'] = True
            ipa_objects.append({
                'Properties': ipa_object,
                'Edges': edges
            })
        return ipa_objects
