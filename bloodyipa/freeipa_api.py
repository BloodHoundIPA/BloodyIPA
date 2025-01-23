import logging

from python_freeipa import ClientMeta
from python_freeipa import exceptions as ipa_exceptions
from requests import exceptions as requests_exceptions
from bloodyipa import FreeIPA
import base64


class FreeIPAPI(FreeIPA):

    _username: str
    _password: str
    _dc: str
    _verify_ssl: bool
    _client: ClientMeta

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

    def collect_users(self):
        users = []
        edge_rules = {
            'memberof_group': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': uid},
                'target': {'type': 'IPAUserGroup', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberof_netgroup': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': uid},
                'target': {'type': 'IPANetGroup', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberof_sudorule': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': uid},
                'target': {'type': 'IPASudoRule', 'uid': other},
                'edge': {'type': 'IPASudoRuleTo', 'properties': {'isacl': True}}
            },
            'memberof_role': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': uid},
                'target': {'type': 'IPARole', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            },
            'memberof_hbacrule': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': uid},
                'target': {'type': 'IPAHBACRule', 'uid': other},
                'edge': {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
            },
        }
        for data in self._client.user_find(o_sizelimit=0).get('result', []):
            user = dict()
            edges = []
            for key, value in data.items():
                if key in ['krblastpwdchange', 'krbpasswordexpiration', 'krblastadminunlock', 'krblastfailedauth']:
                    user[key] = value[0]['__datetime__']
                elif key == 'krbextradata':
                    user[key] = [base64.b64decode(value[0]['__base64__']).decode('utf-8', errors='ignore')]
                elif key in edge_rules.keys():
                    for other_uid in value:
                        edges.append(edge_rules[key](data['uid'][0], other_uid))
                else:
                    user[key] = value
            user['highvalue'] = 'admins' in data.get('memberof_group', [])
            user['name'] = user['uid'][0]
            user['object_id'] = user['uid'][0]
            users.append({
                    'Properties': user,
                    'Edges': edges
                })
        return users

    def collect_hosts(self):
        hosts = []
        edge_rules = {
            'memberof_hostgroup': lambda uid, other: {
                'source': {'type': 'IPAHost', 'uid': uid},
                'target': {'type': 'IPAHostGroup', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberof_netgroup': lambda uid, other: {
                'source': {'type': 'IPAHost', 'uid': uid},
                'target': {'type': 'IPANetGroup', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberof_sudorule': lambda uid, other: {
                'source': {'type': 'IPASudoRule', 'uid': other},
                'target': {'type': 'IPAHost', 'uid': uid},
                'edge': {'type': 'IPASudoRuleTo', 'properties': {'isacl': True}}
            },
            'memberof_role': lambda uid, other: {
                'source': {'type': 'IPAHost', 'uid': uid},
                'target': {'type': 'IPARole', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            },
            'memberof_hbacrule': lambda uid, other: {
                'source': {'type': 'IPAHost', 'uid': uid},
                'target': {'type': 'IPAHBACRule', 'uid': other},
                'edge': {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
            },
        }
        for data in self._client.host_find(o_sizelimit=0).get('result', []):
            host = dict()
            edges = []
            for key, value in data.items():
                if key in ['krblastpwdchange', 'krbpasswordexpiration', 'krblastadminunlock', 'krblastfailedauth']:
                    host[key] = value[0]['__datetime__']
                elif key == 'krbextradata':
                    host[key] = [base64.b64decode(value[0]['__base64__']).decode('utf-8', errors='ignore')]
                elif key in edge_rules.keys():
                    for other_uid in value:
                        edges.append(edge_rules[key](data['cn'][0], other_uid))
                else:
                    host[key] = value

            host['highvalue'] = 'ipaservers' in data.get('memberof_hostgroup', [])
            host['name'] = host['cn'][0]
            host['object_id'] = host['cn'][0]
            hosts.append({
                'Properties': host,
                'Edges': edges
            })
        return hosts

    def collect_groups(self):
        return self._collect_usergroups() + self._collect_hostgroups() + self._collect_netgroups()

    def _collect_usergroups(self):
        edge_rules = {
            'member_user': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': other},
                'target': {'type': 'IPAUserGroup', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'member_group': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': other}, 
                'target': {'type': 'IPAUserGroup', 'uid': uid}, 
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'member_service': lambda uid, other: {
                'source': {'type': 'IPAService', 'uid': other}, 
                'target': {'type': 'IPAUserGroup', 'uid': uid}, 
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberof_group': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': uid}, 
                'target': {'type': 'IPAUserGroup', 'uid': other}, 
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberof_netgroup': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': uid}, 
                'target': {'type': 'IPANetGroup', 'uid': other}, 
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberof_sudorule': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': uid}, 
                'target': {'type': 'IPASudoRule', 'uid': other}, 
                'edge': {'type': 'IPASudoRuleTo', 'properties': {'isacl': True}}
            },
            'memberof_role': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': uid}, 
                'target': {'type': 'IPARole', 'uid': other}, 
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            },
            'membermanager_user': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': other}, 
                'target': {'type': 'IPAUserGroup', 'uid': uid}, 
                'edge': {'type': 'IPAMemberManager', 'properties': {'isacl': True}}
            },
            'membermanager_group': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': other}, 
                'target': {'type': 'IPAUserGroup', 'uid': uid}, 
                'edge': {'type': 'IPAMemberManager', 'properties': {'isacl': True}}
            },
            'memberof_hbacrule': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': uid},
                'target': {'type': 'IPAHBACRule', 'uid': other},
                'edge': {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
            },
        }
        return self._collect_groups(
            edge_rules,
            self._client.group_find(o_sizelimit=0).get('result', []),
            lambda name: name in ['admins', 'trust admins']
        )

    def _collect_hostgroups(self):
        edge_rules = {
            'member_host': lambda uid, other: {
                'source': {'type': 'IPAHost', 'uid': other},
                'target': {'type': 'IPAHostGroup', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'member_hostgroup': lambda uid, other: {
                'source': {'type': 'IPAHostGroup', 'uid': other},
                'target': {'type': 'IPAHostGroup', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberof_hostgroup': lambda uid, other: {
                'source': {'type': 'IPAHostGroup', 'uid': uid},
                'target': {'type': 'IPAHostGroup', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberof_netgroup': lambda uid, other: {
                'source': {'type': 'IPAHostGroup', 'uid': uid},
                'target': {'type': 'IPANetGroup', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberof_sudorule': lambda uid, other: {
                'source': {'type': 'IPASudoRule', 'uid': other},
                'target': {'type': 'IPAHostGroup', 'uid': uid},
                'edge': {'type': 'IPASudoRuleTo', 'properties': {'isacl': True}}
            },
            'membermanager_user': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': other},
                'target': {'type': 'IPAHostGroup', 'uid': uid},
                'edge': {'type': 'IPAMemberManager', 'properties': {'isacl': True}}
            },
            'membermanager_group': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': other},
                'target': {'type': 'IPAHostGroup', 'uid': uid},
                'edge': {'type': 'IPAMemberManager', 'properties': {'isacl': True}}
            },
            'memberof_hbacrule': lambda uid, other: {
                'source': {'type': 'IPAHostGroup', 'uid': uid},
                'target': {'type': 'IPAHBACRule', 'uid': other},
                'edge': {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
            },
        }
        return self._collect_groups(
            edge_rules,
            self._client.hostgroup_find(o_sizelimit=0).get('result', []),
            lambda name: name == 'ipaservers'
        )

    def _collect_netgroups(self):
        edge_rules = {
            'memberuser_user': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': other},
                'target': {'type': 'IPANetGroup', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberuser_group': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': other},
                'target': {'type': 'IPANetGroup', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberhost_host': lambda uid, other: {
                'source': {'type': 'IPAHost', 'uid': other},
                'target': {'type': 'IPANetGroup', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            },
            'memberhost_hostgroup': lambda uid, other: {
                'source': {'type': 'IPAHostGroup', 'uid': other},
                'target': {'type': 'IPANetGroup', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}
            }
        }
        return self._collect_groups(
            edge_rules,
            self._client.netgroup_find(o_sizelimit=0).get('result', []),
            lambda name: False
        )

    @staticmethod
    def _collect_groups(edge_rules: dict, raw_data: dict, highvalue):
        groups = []
        for data in raw_data:
            group = dict()
            edges = []
            for key, value in data.items():
                if key in ['krblastpwdchange', 'krbpasswordexpiration', 'krblastadminunlock', 'krblastfailedauth']:
                    group[key] = value[0]['__datetime__']
                elif key == 'krbextradata':
                    group[key] = [base64.b64decode(value[0]['__base64__']).decode('utf-8', errors='ignore')]
                elif key in edge_rules.keys():
                    for other_uid in value:
                        edges.append(edge_rules[key](data['cn'][0], other_uid))
                else:
                    group[key] = value
            group['name'] = group['cn'][0]
            group['object_id'] = group['cn'][0]
            group['highvalue'] = highvalue(group['name'])
            groups.append({
                'Properties': group,
                'Edges': edges
            })
        return groups

    def collect_sudo(self):
        return self._collect_sudocmd() + self._collect_sudogroups() + self._collect_sudorule()

    def _collect_sudocmd(self):
        commands = []
        for data in self._client.sudocmd_find(o_sizelimit=0).get('result', []):
            commands.append({
                'Properties': {
                    'objectclass': data.get('objectclass'),
                    'ipauniqueid': data.get('ipauniqueid')[0],
                    'name': data.get('sudocmd')[0],
                    'object_id': data.get('sudocmd')[0],
                    'description': data.get('description', ['-'])[0],
                    'highvalue': False,
                }
            })
        return commands

    def _collect_sudogroups(self):
        groups = []
        for data in self._client.sudocmdgroup_find(o_sizelimit=0).get('result', []):
            groups.append({
                'Properties': {
                    'objectclass': data.get('objectclass'),
                    'ipauniqueid': data.get('ipauniqueid')[0],
                    'name': data.get('cn')[0],
                    'object_id': data.get('cn')[0],
                    'description': data.get('description', ['-'])[0],
                    'highvalue': False
                },
                'Edges': [
                    {'source': {'type': 'IPASudo', 'uid': uid},
                     'target': {'type': 'IPASudoGroup', 'uid': data.get("cn")[0]},
                     'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}}
                    for uid in data.get('member_sudocmd', [])
                ]
            })
        return groups

    def _collect_sudorule(self):
        edge_rules = {
            'memberuser_user': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': other},
                'target': {'type': 'IPASudoRule', 'uid': uid},
                'edge': {'type': 'IPASudoRuleTo', 'properties': {'isacl': True}}
            },
            'memberuser_group': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': other},
                'target': {'type': 'IPASudoRule', 'uid': uid},
                'edge': {'type': 'IPASudoRuleTo', 'properties': {'isacl': True}}
            },
            'memberhost_host': lambda uid, other: {
                'source': {'type': 'IPAHost', 'uid': other},
                'target': {'type': 'IPASudoRule', 'uid': uid},
                'edge': {'type': 'IPASudoRuleTo', 'properties': {'isacl': True}}
            },
            'memberhost_hostgroup': lambda uid, other: {
                'source': {'type': 'IPAHostGroup', 'uid': other},
                'target': {'type': 'IPASudoRule', 'uid': uid},
                'edge': {'type': 'IPASudoRuleTo', 'properties': {'isacl': True}}
            },
            'memberallowcmd_sudocmd': lambda uid, other: {
                'source': {'type': 'IPASudo', 'uid': other},
                'target': {'type': 'IPASudoRule', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False, 'allow': True}}
            },
            'memberallowcmd_sudocmdgroup': lambda uid, other: {
                'source': {'type': 'IPASudoGroup', 'uid': other},
                'target': {'type': 'IPASudoRule', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False, 'allow': True}}
            },
            'memberdenycmd_sudocmd': lambda uid, other: {
                'source': {'type': 'IPASudo', 'uid': other},
                'target': {'type': 'IPASudoRule', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False, 'allow': False}}
            },
            'memberdenycmd_sudocmdgroup': lambda uid, other: {
                'source': {'type': 'IPASudoGroup', 'uid': other},
                'target': {'type': 'IPASudoRule', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False, 'allow': False}}
            }
        }
        rules = []
        for data in self._client.sudorule_find(o_sizelimit=0).get('result', []):
            rule = {
                'objectclass': data.get('objectclass'),
                'ipauniqueid': data.get('ipauniqueid')[0],
                'name': data.get('cn')[0],
                'object_id': data.get('cn')[0],
                'uid': data.get('cn')[0],
                'description': data.get('description', ['-'])[0],
                'ipaenabledflag': data.get('ipaenabledflag')[0],
                'sudoorder': data.get('sudoorder', [''])[0],
                'ipasudoopt': data.get('ipasudoopt', ''),
                'ipasudorunasgroupcategory': data.get('ipasudorunasgroupcategory', []),
                'ipasudorunas_user': data.get('ipasudorunas_user', []),
                'ipasudorunas_group': data.get('ipasudorunas_group', []),
                'ipasudorunasextuser': data.get('ipasudorunasextuser', []),
                'highvalue': 'admin' in data.get('ipasudorunas_user', [])
                             or 'admins' in data.get('ipasudorunas_group', []),
            }
            edges = []
            for key, value in data.items():
                if key in edge_rules.keys():
                    for other_uid in value:
                        edges.append(edge_rules[key](rule['name'], other_uid))
            rules.append({
                'Properties': rule,
                'Edges': edges
            })
        return rules

    def collect_roles(self):
        roles = []
        edge_rules = {
            'member_user': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': other},
                'target': {'type': 'IPARole', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            },
            'member_host': lambda uid, other: {
                'source': {'type': 'IPAHost', 'uid': other},
                'target': {'type': 'IPARole', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            },
            'member_group': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': other},
                'target': {'type': 'IPARole', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            },
            'member_hostgroup': lambda uid, other: {
                'source': {'type': 'IPAHostGroup', 'uid': other},
                'target': {'type': 'IPARole', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            },
            'member_service': lambda uid, other: {
                'source': {'type': 'IPAService', 'uid': other},
                'target': {'type': 'IPARole', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            },
            'memberof_privilege': lambda uid, other: {
                'source': {'type': 'IPARole', 'uid': uid},
                'target': {'type': 'IPAPrivilege', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            }
        }
        for data in self._client.role_find(o_sizelimit=0).get('result', []):
            role = dict()
            edges = []
            for key, value in data.items():
                if key in edge_rules.keys():
                    for other_uid in value:
                        edges.append(edge_rules[key](data['cn'][0], other_uid))
                else:
                    role[key] = value
            role['objectclass'].append('iparole')
            role['name'] = role['cn'][0]
            role['object_id'] = role['cn'][0]
            roles.append({
                'Properties': role,
                'Edges': edges
            })
        return roles

    def collect_privileges(self):
        privileges = []
        edge_rules = {
            'member_role': lambda uid, other: {
                'source': {'type': 'IPARole', 'uid': other},
                'target': {'type': 'IPAPrivilege', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            },
            'memberof_permission': lambda uid, other: {
                'source': {'type': 'IPAPrivilege', 'uid': uid},
                'target': {'type': 'IPAPermission', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            }
        }
        for data in self._client.privilege_find(o_sizelimit=0).get('result', []):
            privilege = dict()
            edges = []
            for key, value in data.items():
                if key in edge_rules.keys():
                    for other_uid in value:
                        edges.append(edge_rules[key](data['cn'][0], other_uid))
                else:
                    privilege[key] = value
            privilege['objectclass'].append('ipaprivilege')
            privilege['name'] = privilege['cn'][0]
            privilege['object_id'] = privilege['cn'][0]
            privileges.append({
                'Properties': privilege,
                'Edges': edges
            })
        return privileges

    def collect_permissions(self):
        permissions = []
        edge_rules = {
            'member_privilege': lambda uid, other: {
                'source': {'type': 'IPAPrivilege', 'uid': other},
                'target': {'type': 'IPAPermission', 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            }
        }
        for data in self._client.permission_find(o_sizelimit=0).get('result', []):
            permission = dict()
            edges = []
            for key, value in data.items():
                if key in edge_rules.keys():
                    for other_uid in value:
                        edges.append(edge_rules[key](data['cn'][0], other_uid))
                else:
                    permission[key] = value
            permission['name'] = permission['cn'][0]
            permission['object_id'] = permission['cn'][0]
            permissions.append({
                'Properties': permission,
                'Edges': edges
            })
        return permissions

    def collect_services(self):
        services = []
        edge_rules = {
            'memberof_role': lambda uid, other: {
                'source': {'type': 'IPAService', 'uid': uid},
                'target': {'type': 'IPARole', 'uid': other},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': True}}
            }
        }
        for data in self._client.service_find(o_sizelimit=0).get('result', []):
            service = dict()
            edges = []
            for key, value in data.items():
                if key in ['krblastpwdchange', 'krbpasswordexpiration', 'krblastadminunlock', 'krblastfailedauth']:
                    service[key] = value[0]['__datetime__']
                elif key in ['krbextradata', 'usercertificate']:
                    service[key] = [base64.b64decode(value[0]['__base64__']).decode('utf-8', errors='ignore')]
                elif key in edge_rules.keys():
                    for other_uid in value:
                        edges.append(edge_rules[key](data['krbprincipalname'][0], other_uid))
                else:
                    service[key] = value
            service['name'] = service['krbprincipalname'][0]
            service['object_id'] = service['krbprincipalname'][0]
            services.append({
                'Properties': service,
                'Edges': edges
            })
        return services

    def collect_hbac(self):
        return self._collect_hbacsvc() + self._collect_hbacsvcgroup() + self._collect_hbacrule()

    def _collect_hbacsvc(self):
        commands = []
        for data in self._client.hbacsvc_find(o_sizelimit=0).get('result', []):
            commands.append({
                'Properties': {
                    'objectclass': data.get('objectclass'),
                    'ipauniqueid': data.get('ipauniqueid')[0],
                    'name': data.get('cn')[0],
                    'object_id': data.get('cn')[0],
                    'description': data.get('description', ['-'])[0],
                    'highvalue': False,
                },
                'Edges': [
                    {'source': {'type': 'IPAHBACService', 'uid': data.get("cn")[0]},
                     'target': {'type': 'IPAHBACServiceGroup', 'uid': uid},
                     'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}}
                    for uid in data.get('memberof_hbacsvcgroup', [])
                ]
            })
        return commands

    def _collect_hbacsvcgroup(self):
        groups = []
        for data in self._client.hbacsvcgroup_find(o_sizelimit=0).get('result', []):
            groups.append({
                'Properties': {
                    'objectclass': data.get('objectclass'),
                    'ipauniqueid': data.get('ipauniqueid')[0],
                    'name': data.get('cn')[0],
                    'object_id': data.get('cn')[0],
                    'description': data.get('description', ['-'])[0],
                    'highvalue': False
                },
                'Edges': [
                    {'source': {'type': 'IPAHBACService', 'uid': uid},
                     'target': {'type': 'IPAHBACServiceGroup', 'uid': data.get("cn")[0]},
                     'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False}}}
                    for uid in data.get('member_hbacsvc', [])
                ]
            })
        return groups

    def _collect_hbacrule(self):
        edge_rules = {
            'memberuser_user': lambda uid, other: {
                'source': {'type': 'IPAUser', 'uid': other},
                'target': {'type': 'IPAHBACRule', 'uid': uid},
                'edge': {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
            },
            'memberuser_group': lambda uid, other: {
                'source': {'type': 'IPAUserGroup', 'uid': other},
                'target': {'type': 'IPAHBACRule', 'uid': uid},
                'edge': {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
            },
            'memberhost_host': lambda uid, other: {
                'source': {'type': 'IPAHost', 'uid': other},
                'target': {'type': 'IPAHBACRule', 'uid': uid},
                'edge': {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
            },
            'memberhost_hostgroup': lambda uid, other: {
                'source': {'type': 'IPAHostGroup', 'uid': other},
                'target': {'type': 'IPAHBACRule', 'uid': uid},
                'edge': {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
            },
            'memberservice_hbacsvc': lambda uid, other: {
                'source': {'type': 'IPAHBACService', 'uid': other},
                'target': {'type': 'IPAHBACRule', 'uid': uid},
                'edge': {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
            },
            'memberservice_hbacsvcgroup': lambda uid, other: {
                'source': {'type': 'IPAHBACServiceGroup', 'uid': other},
                'target': {'type': 'IPAHBACRule', 'uid': uid},
                'edge': {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
            },
        }
        rules = []
        for data in self._client.hbacrule_find(o_sizelimit=0).get('result', []):
            rule = {}
            edges = []
            for key, value in data.items():
                if key in edge_rules.keys():
                    for other_uid in value:
                        edges.append(edge_rules[key](data['cn'][0], other_uid))
                else:
                    rule[key] = value
            rule['name'] = rule['cn'][0]
            rule['object_id'] = rule['cn'][0]
            rules.append({
                'Properties': rule,
                'Edges': edges
            })
        return rules
