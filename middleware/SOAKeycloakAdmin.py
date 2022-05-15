import json

from keycloak import KeycloakAdmin, URL_ADMIN_USER_CLIENT_ROLES, KeycloakGetError, raise_error_from_response, \
    URL_ADMIN_USER

URL_ADMIN_ROLE_BY_ID = "admin/realms/{realm-name}/roles-by-id/{role-id}"


class SOAKeycloakAdmin(KeycloakAdmin):

    def unassign_client_role(self, user_id, client_id, roles):
        """
        Remove a client role from a user

        :param user_id: id of user
        :param client_id: id of client (not client-id)
        :param roles: roles list or role (use RoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self.realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.raw_delete(URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
                                   data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def update_role(self, role):
        """
        Update role attributes

        :param role: role (use RoleRepresentation)
        :return Keycloak server response
        """
        params_path = {"realm-name": self.realm_name, "role-id": role['id']}
        data_raw = self.raw_put(URL_ADMIN_ROLE_BY_ID.format(**params_path),
                                data=json.dumps(role))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])
