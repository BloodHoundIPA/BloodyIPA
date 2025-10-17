import json
import base64
from ldap3 import ALL_ATTRIBUTES, LEVEL


class IPAobjectCollector(object):
    def __init__(self, client, base_dn, timestamp, logger, ipa_type, name, object_id, use_ladp=False, dn='', filter='(objectclass=*)'):
        self.ipa_objects = {'data': [], "meta": {"methods": 0, "type": f"freeipa_{ipa_type}", "count": 0, "version": 6}}
        self.logger = logger
        self.ipa_type = ipa_type
        self.name = name
        self.object_id = object_id
        self.dn = dn
        self.client = client
        self.filter = filter
        self.base_dn = base_dn
        if use_ladp:
            self.collect_from_ldap()
        else:
            self.collect_from_api()
        # self.create_json(timestamp)

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
        properties['name'] = ipa_object[self.name.lower()][0]
        properties['object_id'] = ipa_object[self.object_id.lower()][0]
        properties['highvalue'] = False
        name = properties['object_id']
        for attribute in ipa_object:
            if attribute.startswith('member') and not attribute.count("memberofindirect"):
                for member in ipa_object[attribute]:
                    if attribute.startswith('memberof_'):
                        edges.append(self.edge_builder('memberof', attribute.split('_')[-1], member, name))
                    elif attribute == 'memberof':
                        edges.append(self.edge_builder('memberof', 'group', member, name))
                    elif attribute.startswith("membermanager_"):
                        edges.append(self.edge_builder('membermanager', attribute.split('_')[-1], member, name))
                    # elif attribute.startswith('memberofindirect_'):
                    #     edges.append(self.edge_builder('member', attribute.split('_')[-1], member, name))
                    elif attribute.count("deny") or attribute.count("allow"):
                        edges.append(self.edge_builder(attribute, attribute.split('_')[-1], member, name))
                    else:
                        edges.append(self.edge_builder('member', attribute.split('_')[-1], member, name))
            elif attribute.startswith('manag'):
                for member in ipa_object[attribute]:
                    if attribute.startswith('managedby_'):
                        edges.append(self.edge_builder('managedby', attribute.split('_')[-1], member, name))
                    elif attribute.startswith('managing_'):
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
        member_mapper = {'cn=permissions,cn=pbac': 'permission', 'cn=groups,cn=accounts':'group', 'cn=hostgroups,cn=accounts':'hostgroup', 'cn=ng,cn=alt':'netgroup', 'cn=roles,cn=accounts': 'role', 'cn=sudorules,cn=sudo': 'sudorule', 'cn=sudocmds,cn=sudo': 'sudocmd', 'cn=sudocmdgroups,cn=sudo': 'sudocmdgroup', 'cn=hbac': 'hbacrule', 'cn=privileges,cn=pbac': 'privilege', 'cn=computers,cn=accounts': 'host', 'cn=users,cn=accounts': 'user', 'cn=services,cn=accounts': 'service', 'cn=trusts': 'trust', 'cn=sysaccounts,cn=etc': 'sysaccounts', 'cn=hbacservices,cn=hbac': 'hbacservices', 'cn=hbacservicegroups,cn=hbac': 'hbacservicegroups', 'cn=subids,cn=accounts': 'subids'}
        edges = []
        properties = {}
        entry_lower = {'attributes': dict()}
        for key, value in entry['attributes'].items():
            entry_lower['attributes'][key.lower()] = value
        properties['name'] = entry_lower['attributes'][self.name.lower()][0]
        properties['object_id'] = entry_lower['attributes'][self.object_id.lower()][0]
        properties['highvalue'] = False
        name = properties['object_id']
        for attribute in entry_lower['attributes']:
            if 'manag' in attribute.lower():
                for member in entry_lower['attributes'][attribute]:
                    member = member[:-len(self.base_dn)-1]
                    member, path = member.split(',', 1)
                    mapped_type = member_mapper[path]
                    if attribute == 'managedBy'.lower():
                        edges.append(self.edge_builder('managedby', mapped_type, member.split('=', 1)[-1], name))
                    if attribute == 'memberManager'.lower():
                        edges.append(self.edge_builder('membermanager', mapped_type, member.split('=', 1)[-1], name))
            elif attribute.startswith('member'):
                for member in entry_lower['attributes'][attribute]:
                    member = member[:-len(self.base_dn)-1]
                    member, path = member.split(',', 1)
                    mapped_type = member_mapper[path]
                    edges.append(self.edge_builder(attribute.lower(), mapped_type, member.split('=', 1)[-1], name))
            else:
                if len(entry_lower['attributes'][attribute]) == 1:
                    properties[attribute.lower()] = entry_lower['attributes'][attribute][0]
                else:
                    properties[attribute.lower()] = entry_lower['attributes'][attribute]
                if isinstance(entry_lower['attributes'][attribute], dict) and 'encoding' in entry_lower['attributes'][attribute].keys():
                    properties[attribute.lower()] = entry_lower['attributes']['encoded']
                if isinstance(properties[attribute.lower()], dict):
                    properties[attribute.lower()] = [f'{key}: {value}' for key, value in properties[attribute.lower()].items()]
        return properties, edges


    def edge_builder(self, relation_type, target_type, target, source_name):
        ipa_type_mapper = {'user': 'IPAUser', 'group': 'IPAUserGroup', 'privilege': 'IPAPrivilege', 'permission': 'IPAPermission', 'sudorule': 'IPASudoRule', 'role': 'IPARole', 'hostgroup': 'IPAHostGroup', 'netgroup': 'IPANetGroup', 'hbacrule': 'IPAHBACRule', 'host': 'IPAHost', 'sysaccounts':'IPASysAccount', 'service': 'IPAService', 'sudocmd': 'IPASudo', 'sudocmdgroup': 'IPASudoGroup', 'hbacservices': 'IPAHBACService', 'hbacservicegroups': 'IPAHBACServiceGroup', 'hbacsvc': 'IPAHBACService', 'hbacsvcgroup': 'IPAHBACServiceGroup', 'subids': 'IPASubId', 'subid': 'IPASubId'}
        acl_type_mapper = {'sudorule': 'IPASudoRuleTo', 'hbacrule': 'IPAHBACRuleTo', 'permission': 'IPAMemberOf', 'privilege': 'IPAMemberOf'}

        if self.ipa_type in acl_type_mapper:
            edge = {'source': {'type': ipa_type_mapper[target_type], 'uid': target}, 'target': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'edge': {'type': "IPAMemberOf" if ipa_type_mapper[target_type] in ["IPASudo", "IPASudoGroup", "IPAHBACService", "IPAHBACServiceGroup"] else acl_type_mapper[self.ipa_type], "properties": {"isacl": True}}}
            if 'deny' in relation_type or 'allow' in relation_type:
                edge['edge']['properties']['allow'] = 'allow' in relation_type
        elif target_type in acl_type_mapper:
            edge = {'source': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'target': {'type': ipa_type_mapper[target_type], 'uid': target}, 'edge': {'type': "IPAMemberOf" if ipa_type_mapper[self.ipa_type] in ["IPASudo", "IPASudoGroup", "IPAHBACService", "IPAHBACServiceGroup"] else acl_type_mapper[target_type], "properties": {"isacl": True}}}
        elif relation_type == 'managedby':
            edge = {'source': {'type': ipa_type_mapper[target_type], 'uid': target}, 'target': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'edge': {'type': 'IPAManagedBy', "properties": {"isacl": True}}}
        elif relation_type == 'managing':
            edge = {'source': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'target': {'type': ipa_type_mapper[target_type], 'uid': target}, 'edge': {'type': 'IPAManagedBy', "properties": {"isacl": True}}}
        elif relation_type == 'membermanager':
            edge = {'source': {'type': ipa_type_mapper[target_type], 'uid': target},
                    'target': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name},
                    'edge': {'type': 'IPAMemberManager', "properties": {"isacl": True}}}
        else:
            if relation_type == 'memberof':
                edge = {'source': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'target': {'type': ipa_type_mapper[target_type], 'uid': target}, 'edge': {'type': 'IPAMemberOf', "properties": {"isacl": False}}}
            else:
                edge = {'source': {'type': ipa_type_mapper[target_type], 'uid': target}, 'target': {'type': ipa_type_mapper[self.ipa_type], 'uid': source_name}, 'edge': {'type': 'IPAMemberOf', "properties": {"isacl": False}}}
        return edge

    def create_json(self, file_name: str):
        with open(file_name, 'w') as f:
            f.write(json.dumps(self.ipa_objects, indent=2))
        self.logger.info(f'\tsaved {self.ipa_type}s to file {file_name}')


    def parse_user_rights(self, uid):
        rights = self.client.user_show(uid)['result']['attributelevelrights']

