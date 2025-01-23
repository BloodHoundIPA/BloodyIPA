from bloodyipa import FreeIPA
from ldap3 import Server, Connection, SIMPLE, ALL, ANONYMOUS, ALL_ATTRIBUTES, LEVEL
import datetime
import logging


LDAP_TREE = {
    'accounts': {
        'users': {'type': 'IPAUser'},
        'groups': {'type': 'IPAUserGroup'},
        'roles': {'type': 'IPARole'},
        'computers': {'type': 'IPAHost'},
        'hostgroups': {'type': 'IPAHostGroup'},
        'services': {'type': 'IPAService'},
        'subids': {'type': 'IPASubId'}    #   TODO: add to ui
    },
    'alt': {
        'ng': {'type': 'IPANetGroup'},
    },
    'pbac': {
        'privileges': {'type': 'IPAPrivilege'},
        'permissions': {'type': 'IPAPermission'}
    },
    'sudo': {
        'sudocmdgroups': {'type': 'IPASudoGroup'},
        'sudocmds': {'type': 'IPASudo'},
        'sudorules': {'type': 'IPASudoRule'}
    },
    'hbac': {
        'hbacservicegroups': {'type': 'IPAHBACServiceGroup'},
        'hbacservices': {'type': 'IPAHBACService'},
        'type': 'IPAHBACRule'
    },
    'etc': {
        'sysaccounts': {'type': 'IPASysAccount'}    #   TODO: add to ui
    }
}


class FreeIPALDAP(FreeIPA):

    _connection: Connection
    _dc: str

    def __init__(self, ip: str, dc: str, user: str = None, password: str = None, protocol: str = "ldaps"):
        server = Server(f"{protocol}://{ip}:{'636' if protocol == 'ldaps' else '389'}", get_info=ALL)
        self._dc = ','.join([f'dc={part}' for part in dc.split('.')])
        self._logger = logging.getLogger('ldap')
        if all((user, password)):
            self._auth_simple(server, user, password)
        else:
            self._auth_anonymous(server)

    def _auth_simple(self, server: Server, user: str, password: str):

        self._connection = Connection(
            server,
            user=f'uid={user},cn=users,cn=accounts,{self._dc}',
            password=password,
            authentication=SIMPLE
        )
        self._connection.bind()

    def _auth_anonymous(self, server: Server):
        self._connection = Connection(server, authentication=ANONYMOUS)
        self._connection.bind()

    def collect_users(self):
        self._connection.search(
            f'cn=users,cn=accounts,{self._dc}',
            '(uid=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )

        return self._collect_ipa_objects(
            'IPAUser',
            'uid',
            'uid',
            lambda edge: edge['target']['type'] == 'IPAUserGroup'
            and edge['target']['uid'] == 'admins'
        )

    def collect_hosts(self):
        self._connection.search(
            f'cn=computers,cn=accounts,{self._dc}',
            '(fqdn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._collect_ipa_objects(
            'IPAHost',
            'fqdn',
            'fqdn',
            lambda edge: edge['target']['type'] == 'IPAHostGroup'
            and edge['target']['uid'] == 'ipaservers'
        )

    def collect_groups(self):
        return self._collect_usergroups() + self._collect_hostgroups() + self._collect_netgroups()

    def _collect_usergroups(self):
        self._connection.search(
            f'cn=groups,cn=accounts,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._collect_ipa_objects(
            'IPAUserGroup',
            'cn',
            'cn',
            lambda edge: edge['target']['type'] == 'IPAUserGroup'
            and edge['target']['uid'] in ['admins', 'trust admins']
        )

    def _collect_hostgroups(self):
        self._connection.search(
            f'cn=hostgroups,cn=accounts,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._collect_ipa_objects(
            'IPAHostGroup',
            'cn',
            'cn',
            lambda edge: edge['target']['type'] == 'IPAHostGroup'
            and edge['target']['uid'] == 'ipaservers'
        )

    def _collect_netgroups(self):
        self._connection.search(
            f'cn=ng,cn=alt,{self._dc}',
            '(&(ipaUniqueID=*)(!(mepManagedBy=*)))',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        ipaUniqueID = self._collect_ipa_objects(
            'IPANetGroup',
            'cn',
            'ipaUniqueID',
            lambda edge: False
        )
        self._connection.search(
            f'cn=ng,cn=alt,{self._dc}',
            '(&(ipaUniqueID=*)(mepManagedBy=*))',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        cn = self._collect_ipa_objects(
            'IPANetGroup',
            'cn',
            'cn',
            lambda edge: False
        )
        return ipaUniqueID + cn

    def collect_sudo(self):
        return self._collect_sudocmd() + self._collect_sudogroups() + self._collect_sudorule()

    def _collect_sudocmd(self):
        self._connection.search(
            f'cn=sudocmds,cn=sudo,{self._dc}',
            '(ipaUniqueID=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._collect_ipa_objects(
            'IPASudo',
            'sudoCmd',
            'ipaUniqueID',
            lambda edge: False
        )

    def _collect_sudogroups(self):

        self._connection.search(
            f'cn=sudocmdgroups,cn=sudo,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._collect_ipa_objects(
            'IPASudoGroup',
            'cn',
            'cn',
            lambda edge: False
        )

    def _collect_sudorule(self):
        self._connection.search(
            f'cn=sudorules,cn=sudo,{self._dc}',
            '(ipaUniqueID=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        sudo_rules = self._collect_ipa_objects(
            'IPASudoRule',
            'cn',
            'ipaUniqueID',
            lambda edge: False
        )
        for sudo in sudo_rules:
            run_as_objects = sudo['Properties'].get('ipaSudoRunAs', [])
            if type(run_as_objects) is not list:
                run_as_objects = [run_as_objects]
            for run_as_object in run_as_objects:
                _run_as_object = self._convert(run_as_object)
                if (_run_as_object['type'] == 'IPAUser' and _run_as_object['value'] == 'admin') or (
                        _run_as_object['type'] == 'IPAUserGroup'
                        and _run_as_object['value'] in ['trust admins', 'admins']
                ):
                    sudo['Properties']['highvalue'] = True
        return sudo_rules

    def collect_privileges(self):
        self._connection.search(
            f'cn=privileges,cn=pbac,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        privileges = self._collect_ipa_objects(
            'IPAPrivilege',
            'cn',
            'cn',
            lambda edge: False
        )
        for privilege in privileges:
            privilege['Properties']['objectClass'.lower()].append('ipaprivilege')
        return privileges

    def collect_permissions(self):
        self._connection.search(
            f'cn=permissions,cn=pbac,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._collect_ipa_objects(
            'IPAPermission',
            'cn',
            'cn',
            lambda edge: False
        )

    def collect_roles(self):
        self._connection.search(
            f'cn=roles,cn=accounts,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        ipa_roles = self._collect_ipa_objects(
            'IPARole',
            'cn',
            'cn',
            lambda edge: False
        )
        for ipa_role in ipa_roles:
            ipa_role['Properties']['objectClass'.lower()].append('iparole')
        return ipa_roles

    def collect_services(self):
        self._connection.search(
            f'cn=services,cn=accounts,{self._dc}',
            '(krbprincipalname=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._collect_ipa_objects(
            'IPAService',
            'krbPrincipalName',
            'krbprincipalname',
            lambda edge: False
        )

    def collect_hbac(self):
        return self._collect_hbacservicegroups() + self._collect_hbacservices() + self._collect_hbacrule()

    def _collect_hbacservicegroups(self):
        self._connection.search(
            f'cn=hbacservicegroups,cn=hbac,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._collect_ipa_objects(
            'IPAHBACServiceGroup',
            'cn',
            'cn',
            lambda edge: False
        )

    def _collect_hbacservices(self):
        self._connection.search(
            f'cn=hbacservices,cn=hbac,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._collect_ipa_objects(
            'IPAHBACService',
            'cn',
            'cn',
            lambda edge: False
        )

    def _collect_hbacrule(self):
        self._connection.search(
            f'cn=hbac,{self._dc}',
            '(ipaUniqueID=*)', LEVEL,
            attributes=ALL_ATTRIBUTES
        )
        return self._collect_ipa_objects(
            'IPAHBACRule',
            'cn',
            'ipaUniqueID',
            lambda edge: False
        )

    def _collect_ipa_objects(self, object_type: str, name: str, object_id: str, highvalue_func):
        edge_rules = {
            'member': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': self._edge(other_type, object_type)
            },
            'memberHost': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': self._edge(other_type, object_type)
            },
            'memberUser': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': self._edge(other_type, object_type)
            },
            'memberService': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': self._edge(other_type, object_type)
            },
            'memberAllowCmd': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False, 'allow': True}}
            },
            'memberDenyCmd': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': {'type': 'IPAMemberOf', 'properties': {'isacl': False, 'allow': False}}
            },
            'memberOf': lambda uid, other, other_type: {
                'source': {'type': object_type, 'uid': uid},
                'target': {'type': other_type, 'uid': other},
                'edge': self._edge(object_type, other_type)
            },
            'memberManager': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': {'type': 'IPAMemberManager', 'properties': {'isacl': True}}
            },
            'managedBy': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': {'type': 'IPAMemberManager', 'properties': {'isacl': True}}
            },
            'mepManagedBy': lambda uid, other, other_type: {
                'source': {'type': other_type, 'uid': other},
                'target': {'type': object_type, 'uid': uid},
                'edge': {'type': 'IPAMemberManager', 'properties': {'isacl': True}}
            }
        }
        ipa_objects = []
        for data in self._connection.entries:
            ipa_object, edges = dict(), list()
            for attribute in data.entry_attributes:
                if attribute in edge_rules.keys():
                    for member in data[attribute].values:
                        try:
                            other_object = self._convert(member)
                            edges.append(edge_rules[attribute](
                                data[object_id].value, other_object['value'], other_object['type']
                            ))
                        except KeyError:
                            self._logger.warning(f'Skip {member} in {attribute} on {object_type}')
                elif attribute == 'krbExtraData':
                    ipa_object['krbExtraData'] = data['krbExtraData'].value.decode('utf-8', errors='ignore')
                else:
                    if len(data[attribute].values) > 1:
                        ipa_object[attribute.lower()] = list(map(
                            lambda v: str(v) if type(v) in [datetime.datetime, bytes] else v,
                            data[attribute].values
                        ))
                    else:
                        value = data[attribute].values[0]
                        ipa_object[attribute.lower()] = str(value) if type(value) in [datetime.datetime, bytes] else value
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

    @staticmethod
    def _convert(line: str):
        path = line.split(',')[::-1]
        current = None
        for index in range(len(path)-1):
            key, value = path[index].split('=')
            if key == 'dc':
                continue
            if current:
                current = current[value]
            else:
                current = LDAP_TREE[value]
        return {'type': current['type'], 'value': path[-1].split('=')[1]}

    @staticmethod
    def _edge(first_type: str, second_type: str):
        is_acl = ['IPARole', 'IPAPermission', 'IPAPrivilege']
        if second_type == 'IPAHBACRule':
            if first_type in ['IPAUser', 'IPAUserGroup', 'IPAHost', 'IPAHostGroup']:
                return {'type': 'IPAHBACRuleTo', 'properties': {'isacl': True}}
        if second_type == 'IPASudoRule':
            if first_type in ['IPAUser', 'IPAUserGroup', 'IPAHost', 'IPAHostGroup']:
                return {'type': 'IPASudoRuleTo', 'properties': {'isacl': True}}
        return {'type': 'IPAMemberOf', 'properties': {'isacl': second_type in is_acl}}
