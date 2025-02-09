from bloodyipa.freeipa import FreeIPA
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

    def __init__(self, ip: str, dc: str, user: str = None, password: str = None, protocol: str = "ldaps", auth_type: str = "ANONYMOUS"):
        server = Server(f"{protocol}://{ip}:{'636' if protocol == 'ldaps' else '389'}", get_info=ALL)
        self._dc = ','.join([f'dc={part}' for part in dc.split('.')])
        self._logger = logging.getLogger('ldap')
        if auth_type == 'SIMPLE':
            self._auth_simple(server, user, password)
        elif auth_type == 'ANONYMOUS':
            self._auth_anonymous(server)
        else:
            raise Exception('The authentication method is not supported')

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

    def _collect_users(self):
        self._connection.search(
            f'cn=users,cn=accounts,{self._dc}',
            '(uid=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_hosts(self):
        self._connection.search(
            f'cn=computers,cn=accounts,{self._dc}',
            '(fqdn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_usergroups(self):
        self._connection.search(
            f'cn=groups,cn=accounts,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_hostgroups(self):
        self._connection.search(
            f'cn=hostgroups,cn=accounts,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_netgroups(self):
        self._connection.search(
            f'cn=ng,cn=alt,{self._dc}',
            '(&(ipaUniqueID=*)(mepManagedBy=*))',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_admin_netgroups(self):
        self._connection.search(
            f'cn=ng,cn=alt,{self._dc}',
            '(&(ipaUniqueID=*)(!(mepManagedBy=*)))',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_sudocmd(self):
        self._connection.search(
            f'cn=sudocmds,cn=sudo,{self._dc}',
            '(ipaUniqueID=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_sudogroups(self):
        self._connection.search(
            f'cn=sudocmdgroups,cn=sudo,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_sudorule(self):
        self._connection.search(
            f'cn=sudorules,cn=sudo,{self._dc}',
            '(ipaUniqueID=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_privileges(self):
        self._connection.search(
            f'cn=privileges,cn=pbac,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_permissions(self):
        self._connection.search(
            f'cn=permissions,cn=pbac,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_roles(self):
        self._connection.search(
            f'cn=roles,cn=accounts,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_services(self):
        self._connection.search(
            f'cn=services,cn=accounts,{self._dc}',
            '(krbprincipalname=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_hbacservicegroups(self):
        self._connection.search(
            f'cn=hbacservicegroups,cn=hbac,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_hbacservices(self):
        self._connection.search(
            f'cn=hbacservices,cn=hbac,{self._dc}',
            '(cn=*)',
            LEVEL, attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_hbacrule(self):
        self._connection.search(
            f'cn=hbac,{self._dc}',
            '(ipaUniqueID=*)', LEVEL,
            attributes=ALL_ATTRIBUTES
        )
        return self._connection.entries

    def _collect_ipa_objects(self, raw_data: list, object_type: str, name: str, object_id: str, highvalue_func):
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
        for data in raw_data:
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
                    ipa_object['krbExtraData'.lower()] = data['krbExtraData'].value.decode('utf-8', errors='ignore')
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

