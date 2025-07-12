import json
import base64
from ldap3 import ALL_ATTRIBUTES, LEVEL


class IPAobjectCollector(object):
    def __init__(self, client, dc, timestamp, logger, ipa_type, use_ladp=False, dn='', filter='(objectclass=*)'):
        self.ipa_objects = {'data': [], "meta": {"methods": 0, "type": "freeipa", "count": 0, "version": 6}}
        self.logger = logger
        self.ipa_type = ipa_type
        self.dn = dn
        self.client = client
        self.filter = filter
        self.base_dn = ','.join([f'DC={i}' for i in dc.split('.')[1:]])
        if use_ladp:
            self.collect_from_ldap()
        else:
            self.collect_from_api()
        self.create_json(timestamp)


    def collect_from_api(self):
        ipa_find = getattr(self.client, f'{self.ipa_type}_find')
        ipa_objects = ipa_find(o_sizelimit=0)
        if ipa_objects['result']:
            for ipa_object in ipa_objects['result']:
                properties, edges = self.api_parse_objects(ipa_object)
                self.ipa_objects['data'].append({'Properties': properties, 'Edges': edges})
                count = len(self.ipa_objects['data'])
                self.ipa_objects['meta']['count'] = count
            self.logger.info(f'collected {count} {self.ipa_type}...')
        else:
            self.logger.info(f'collected 0 {self.ipa_type}...')


    def api_parse_objects(self, ipa_object):
        edges = []
        properties = {}
        if 'uid' in ipa_object.keys():
            name = ipa_object['uid'][0]
        elif 'cn' in ipa_object.keys():
            name = ipa_object['cn'][0]
        else:
            name = ipa_object['ipauniqueid'][0]
        properties['name'] = name
        properties['object_id'] = name
        properties['highvalue'] = False
        for attribute in ipa_object:
            if attribute.startswith('member'):
                for member in ipa_object[attribute]:
                    if attribute.startswith('memberof_'):
                        edges.append(self.edge_builder('memberof', attribute.split('_')[-1], member, name))
                    elif attribute == 'memberof':
                        edges.append(self.edge_builder('memberof', 'group', member, name))
                    elif attribute.startswith('memberofindirect_'):
                        edges.append(self.edge_builder('member', attribute.split('_')[-1], member, name))
                    else:
                        edges.append(self.edge_builder('member', attribute.split('_')[-1], member, name))
            elif attribute.startswith('manag'):
                for member in ipa_object[attribute]:
                    if attribute.startswith('managedby_'):
                        print(attribute, ipa_object[attribute])
                        edges.append(self.edge_builder('managedby', attribute.split('_')[-1], member, name))
                    elif attribute.startswith('managing_'):
                        print(attribute, ipa_object[attribute])
                        edges.append(self.edge_builder('managing', attribute.split('_')[-1], member, name))
            else:
                if not isinstance(ipa_object[attribute], bool):
                    if isinstance(ipa_object[attribute][0], dict) and '__base64__' in ipa_object[attribute][0].keys():
                        if 'cert' in attribute or '':
                            properties[attribute] = ipa_object[attribute][0]['__base64__']
                        else:
                            properties[attribute] = base64.b64decode(ipa_object[attribute][0]['__base64__']).decode('utf-8', errors='ignore')
                    elif isinstance(ipa_object[attribute][0], dict) and '__datetime__' in ipa_object[attribute][0].keys():
                        properties[attribute] = ipa_object[attribute][0]['__datetime__']
                    elif len(ipa_object[attribute]) == 1:
                        properties[attribute] = ipa_object[attribute][0]
                    else:
                        properties[attribute] = ipa_object[attribute]
        return properties, edges



    def collect_from_ldap(self):
        self.client.search(f'{self.dn}',self.filter, LEVEL, attributes=ALL_ATTRIBUTES)
        if self.client.entries:
            for entry in self.client.entries:
                entry = json.loads(entry.entry_to_json())
                entry['attributes']['dn'] = entry['dn']
                properties, edges = self.ldap_parse_entries(entry)
                self.ipa_objects['data'].append({'Properties': properties, 'Edges': edges})
                count = len(self.ipa_objects['data'])
                self.ipa_objects['meta']['count'] = count
            self.logger.info(f'collected {count} {self.ipa_type}...')
        else:
            self.logger.info(f'collected 0 {self.ipa_type}...')


    def ldap_parse_entries(self, entry):
        member_mapper = {'cn=permissions,cn=pbac': 'permission', 'cn=groups,cn=accounts':'group', 'cn=hostgroups,cn=accounts':'hostgroup', 'cn=ng,cn=alt':'netgroup', 'cn=roles,cn=accounts': 'role', 'cn=sudorules,cn=sudo': 'sudorule', 'cn=sudocmds,cn=sudo': 'sudocmd', 'cn=sudocmdgroups,cn=sudo': 'sudocmdgroup', 'cn=hbac': 'hbacrule', 'cn=privileges,cn=pbac': 'privilege', 'cn=computers,cn=accounts': 'host', 'cn=users,cn=accounts': 'user', 'cn=services,cn=accounts': 'service', 'cn=trusts': 'trust', 'cn=sysaccounts,cn=etc': 'sysaccounts', 'cn=hbacservices,cn=hbac': 'hbacservices', 'cn=hbacservicegroups,cn=hbac': 'hbacservicegroups'}
        edges = []
        properties = {}
        if 'uid' in entry['attributes'].keys():
            name = entry['attributes']['uid'][0]
        elif 'cn' in entry['attributes'].keys():
            name = entry['attributes']['cn'][0]
        else:
            name = entry['attributes']['ipaUniqueID'][0]
        properties['name'] = name
        properties['object_id'] = name
        properties['highvalue'] = False
        for attribute in entry['attributes']:
            if 'manag' in attribute.lower():
                for member in entry['attributes'][attribute]:
                    member = member[:-len(self.base_dn)-1]
                    member, path = member.split(',', 1)
                    mapped_type = member_mapper[path]
                    if attribute == 'mepManagedEntry':
                        edges.append(self.edge_builder('managing', mapped_type, member.split('=', 1)[-1], name))
                    elif attribute == 'managedBy':
                        edges.append(self.edge_builder('managedby', mapped_type, member.split('=', 1)[-1], name))
                    elif attribute == 'mepManagedBy':
                        edges.append(self.edge_builder('managedby', mapped_type, member.split('=', 1)[-1], name))
            elif attribute.startswith('member'):
                for member in entry['attributes'][attribute]:
                    member = member[:-len(self.base_dn)-1]
                    member, path = member.split(',', 1)
                    mapped_type = member_mapper[path]
                    edges.append(self.edge_builder(attribute.lower(), mapped_type, member.split('=', 1)[-1], name))
            else:
                if len(entry['attributes'][attribute]) == 1:
                    properties[attribute.lower()] = entry['attributes'][attribute][0]
                else:
                    properties[attribute.lower()] = entry['attributes'][attribute]
                if isinstance(entry['attributes'][attribute], dict) and 'encoding' in entry['attributes'][attribute].keys():
                    properties[attribute.lower()] = entry['attributes']['encoded']
        return properties, edges


    def edge_builder(self, relation_type, target_type, target, source_name):
        ipa_type_mapper = {'user': 'IPAUser', 'group': 'IPAUserGroup', 'privilege': 'IPAPrivilege', 'permission': 'IPApermission', 'sudorule': 'IPASudoRule', 'role': 'IPARole', 'hostgroup': 'IPAHostGroup', 'netgroup': 'IPANetGroup', 'hbacrule': 'IPAHBACRule', 'host': 'IPAHost', 'sysaccounts':'IPASysAccount', 'service': 'IPAService', 'sudocmd': 'IPASudo', 'sudocmdgroup': 'IPASudoGroup', 'hbacservices': 'IPAHBACService', 'hbacservicegroups': 'IPAHBACServiceGroup', 'hbacsvc': 'IPAHBACService', 'hbacsvcgroup': 'IPAHBACServiceGroup'}
        acl_type_mapper = {'sudorule': 'IPASudoRuleTo', 'hbacrule': 'IPAHBACRuleTo', 'permission': 'IPAMemberOf', 'privilege': 'IPAMemberOf'}

        if self.ipa_type in acl_type_mapper:
            edge = {'source': {'type': ipa_type_mapper[target_type], 'uid': target}, 'target': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'edge': {'type': acl_type_mapper[self.ipa_type], "properties": {"isacl": True}}}
            if 'deny' in relation_type or 'allow' in relation_type:
                edge['edge']['properties']['allow'] = 'allow' in relation_type
        elif target_type in acl_type_mapper:
            edge = {'source': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'target': {'type': ipa_type_mapper[target_type], 'uid': target}, 'edge': {'type': acl_type_mapper[target_type], "properties": {"isacl": True}}}
        elif relation_type == 'managedby':
            edge = {'source': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'target': {'type': ipa_type_mapper[target_type], 'uid': target}, 'edge': {'type': 'IPAMemberManager', "properties": {"isacl": True}}}
        elif relation_type == 'managing':
            edge = {'source': {'type': ipa_type_mapper[target_type], 'uid': target}, 'target': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'edge': {'type': 'IPAMemberManager', "properties": {"isacl": True}}}
        else:
            if relation_type == 'memberof':
                edge = {'source': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'target': {'type': ipa_type_mapper[target_type], 'uid': target}, 'edge': {'type': 'IPAMemberOf', "properties": {"isacl": False}}}
            else:
                edge = {'source': {'type': ipa_type_mapper[target_type], 'uid': target}, 'target': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'edge': {'type': 'IPAMemberOf', "properties": {"isacl": False}}}
        return edge


    def create_json(self, timestamp):
        with open(f'{timestamp}_ipa_{self.ipa_type}s.json', 'w') as f:
            f.write(json.dumps(self.ipa_objects))
        self.logger.info(f'\tsaved {self.ipa_type}s to file {timestamp}_ipa_{self.ipa_type}s.json')


    def parse_user_rights(self, uid):
        rights = self.client.user_show(uid)['result']['attributelevelrights']

