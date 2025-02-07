class FreeIPA(object):

    def collect_users(self):
        return self._collect_ipa_objects(
            self._collect_users(),
            'IPAUser',
            'uid',
            'uid',
            lambda edge: edge['target']['type'] == 'IPAUserGroup'
            and edge['target']['uid'] == 'admins'
        )

    def _collect_users(self):
        raise Exception('The method is not implemented')

    def collect_hosts(self):
        return self._collect_ipa_objects(
            self._collect_hosts(),
            'IPAHost',
            'fqdn',
            'fqdn',
            lambda edge: edge['target']['type'] == 'IPAHostGroup'
            and edge['target']['uid'] == 'ipaservers'
        )

    def _collect_hosts(self):
        raise Exception('The method is not implemented')

    def collect_groups(self):
        return self.collect_usergroups() + self.collect_hostgroups() + self.collect_netgroups()

    def collect_usergroups(self):
        return self._collect_ipa_objects(
            self._collect_usergroups(),
            'IPAUserGroup',
            'cn',
            'cn',
            lambda edge: edge['target']['type'] == 'IPAUserGroup'
            and edge['target']['uid'] in ['admins', 'trust admins']
        )

    def _collect_usergroups(self):
        raise Exception('The method is not implemented')

    def collect_hostgroups(self):
        return self._collect_ipa_objects(
            self._collect_hostgroups(),
            'IPAHostGroup',
            'cn',
            'cn',
            lambda edge: edge['target']['type'] == 'IPAHostGroup'
            and edge['target']['uid'] == 'ipaservers'
        )

    def _collect_hostgroups(self):
        raise Exception('The method is not implemented')

    def collect_netgroups(self):
        groups = self._collect_ipa_objects(
            self._collect_netgroups(),
            'IPANetGroup',
            'cn',
            'cn',
            lambda edge: False
        )
        admin_groups = self._collect_ipa_objects(
            self._collect_admin_netgroups(),
            'IPANetGroup',
            'cn',
            'ipaUniqueID',
            lambda edge: False
        )
        return groups + admin_groups

    def _collect_netgroups(self):
        raise Exception('The method is not implemented')

    def _collect_admin_netgroups(self):
        return []

    def collect_sudo(self):
        return self.collect_sudocmd() + self.collect_sudogroups() + self.collect_sudorule()

    def collect_sudocmd(self):
        return self._collect_ipa_objects(
            self._collect_sudocmd(),
            'IPASudo',
            'sudoCmd',
            'ipaUniqueID',
            lambda edge: False
        )

    def _collect_sudocmd(self):
        raise Exception('The method is not implemented')

    def collect_sudogroups(self):
        return self._collect_ipa_objects(
            self._collect_sudogroups(),
            'IPASudoGroup',
            'cn',
            'cn',
            lambda edge: False
        )

    def _collect_sudogroups(self):
        raise Exception('The method is not implemented')

    def collect_sudorule(self):
        return self._collect_ipa_objects(
            self._collect_sudorule(),
            'IPASudoRule',
            'cn',
            'ipaUniqueID',
            lambda edge: False
        )

    def _collect_sudorule(self):
        raise Exception('The method is not implemented')

    def collect_privileges(self):
        privileges = self._collect_ipa_objects(
            self._collect_privileges(),
            'IPAPrivilege',
            'cn',
            'cn',
            lambda edge: False
        )
        for privilege in privileges:
            privilege['Properties']['objectClass'.lower()].append('ipaprivilege')
        return privileges

    def _collect_privileges(self):
        raise Exception('The method is not implemented')

    def collect_permissions(self):
        return self._collect_ipa_objects(
            self._collect_permissions(),
            'IPAPermission',
            'cn',
            'cn',
            lambda edge: False
        )

    def _collect_permissions(self):
        raise Exception('The method is not implemented')

    def collect_roles(self):
        ipa_roles = self._collect_ipa_objects(
            self._collect_roles(),
            'IPARole',
            'cn',
            'cn',
            lambda edge: False
        )
        for ipa_role in ipa_roles:
            ipa_role['Properties']['objectClass'.lower()].append('iparole')
        return ipa_roles

    def _collect_roles(self):
        raise Exception('The method is not implemented')

    def collect_services(self):
        return self._collect_ipa_objects(
            self._collect_services(),
            'IPAService',
            'krbPrincipalName',
            'krbprincipalname',
            lambda edge: False
        )

    def _collect_services(self):
        raise Exception('The method is not implemented')

    def collect_hbac(self):
        return self.collect_hbacservicegroups() + self.collect_hbacservices() + self.collect_hbacrule()

    def collect_hbacservicegroups(self):
        return self._collect_ipa_objects(
            self._collect_hbacservicegroups(),
            'IPAHBACServiceGroup',
            'cn',
            'cn',
            lambda edge: False
        )

    def _collect_hbacservicegroups(self):
        raise Exception('The method is not implemented')

    def collect_hbacservices(self):
        return self._collect_ipa_objects(
            self._collect_hbacservices(),
            'IPAHBACService',
            'cn',
            'cn',
            lambda edge: False
        )

    def _collect_hbacservices(self):
        raise Exception('The method is not implemented')

    def collect_hbacrule(self):
        return self._collect_ipa_objects(
            self._collect_hbacrule(),
            'IPAHBACRule',
            'cn',
            'ipaUniqueID',
            lambda edge: False
        )

    def _collect_hbacrule(self):
        raise Exception('The method is not implemented')

    def _collect_ipa_objects(self, raw_data: list, object_type: str, name: str, object_id: str, highvalue_func):
        raise Exception('The method is not implemented')

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
