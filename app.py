from flask import Flask, request, abort
import connexion
from keycloak import KeycloakOpenID
from keycloak import KeycloakAdmin

keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/auth/",
                                 client_id="account",
                                 realm_name="master", client_secret_key='nlpMjHfGrkTjScyZlRivG6gIxpf5KAkH')

keycloak_admin = KeycloakAdmin(server_url="http://localhost:8080/auth/", client_id='account',
                               client_secret_key='nlpMjHfGrkTjScyZlRivG6gIxpf5KAkH', username='admin', password="kosta")

client_id = keycloak_admin.get_client_id('account')


def setup_roles():
    roles = keycloak_admin.get_client_roles(client_id)
    role_names = [role['name'] for role in roles]
    if 'customer' not in role_names:
        keycloak_admin.create_client_role(client_id, {'name': 'customer', 'clientRole': True})
    if 'employee' not in role_names:
        keycloak_admin.create_client_role(client_id, {'name': 'employee', 'clientRole': True})
    if 'admin' not in role_names:
        keycloak_admin.create_client_role(client_id, {'name': 'admin', 'clientRole': True})


def register_customer(register_body):
    username = register_body['username']
    password = register_body['password']

    user_id = keycloak_admin.create_user({"email": username + "@gmail.com",
                                          "username": username,
                                          "enabled": True,
                                          "credentials": [{"value": password, "type": "password", }]}, exist_ok=True)
                                          # "credentials": [{"value": password, "type": "password", }]}, exist_ok=False)

    role = keycloak_admin.get_client_role(client_id=client_id, role_name="customer")
    keycloak_admin.assign_client_role(client_id=client_id, user_id=user_id, roles=[role])

    token = keycloak_openid.token(username, password)

    return get_token_response(token)


def auth(auth_body):
    username = auth_body['username']
    password = auth_body['password']

    token = keycloak_openid.token(username, password)
    return get_token_response(token)


def register_employee(register_employee_body):
    auth_header = request.headers['Authorization']
    token = auth_header.split(" ")[1]

    if not contains_role('admin', token):
        abort(401)

    username = register_employee_body['username']
    password = register_employee_body['password']
    roles = register_employee_body['roles']

    user_id = keycloak_admin.create_user({"email": username,
                                          "username": username,
                                          "enabled": True,
                                          "credentials": [{"value": password, "type": "password", }]}, exist_ok=False)

    for role in roles:
        r = keycloak_admin.get_client_role(client_id=client_id, role_name=role)
        keycloak_admin.assign_client_role(client_id=client_id, user_id=user_id, roles=[r])

    token = keycloak_openid.token(username, password)

    return get_token_response(token)


def create_role(create_role_body):
    keycloak_admin.create_client_role(client_id, {'name': create_role_body['role'], 'clientRole': True})
    return "Role created"


def user_contains_role(role_body):
    auth_header = request.headers['Authorization']
    token = auth_header.split(" ")[1]
    return contains_role(role_body['role'], token)


def refresh_token(refresh_token_body):
    return keycloak_openid.refresh_token(refresh_token_body['refreshToken'])


def logout(refresh_token_body):
    keycloak_openid.logout(refresh_token_body['refreshToken'])


def contains_role(role, token):
    KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
    options = {"verify_signature": True, "verify_aud": False, "verify_exp": True}
    token_info = keycloak_openid.decode_token(token, key=KEYCLOAK_PUBLIC_KEY, options=options)

    if role in token_info['resource_access']['account']['roles']:
        return True

    return False


def user_info():
    auth_header = request.headers['Authorization']
    token = auth_header.split(" ")[1]
    KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
    options = {"verify_signature": True, "verify_aud": False, "verify_exp": True}
    return keycloak_openid.decode_token(token, key=KEYCLOAK_PUBLIC_KEY, options=options)


def get_token_response(token):
    return {"access_token": token['access_token'], "refresh_token": token['refresh_token'],
            "expires_in": token['expires_in'], "refresh_expires_in": token['refresh_expires_in']}


connexion_app = connexion.App(__name__, specification_dir="./")
app = connexion_app.app
connexion_app.add_api("api.yml")

if __name__ == '__main__':
    setup_roles()
    app.run()
