from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from flask import Flask, request, abort
import connexion
from flask_cors import CORS
from keycloak import KeycloakOpenID
from keycloak import KeycloakAdmin
from swagger_ui_bundle import swagger_ui_3_path

import os

load_dotenv()

CLIENT_NAME = "soa-account"

keycloak_openid = KeycloakOpenID(server_url=os.environ['KEYCLOAK_URI'],
                                 client_id=os.environ['KEYCLOAK_CLIENT_ID'],
                                 realm_name=os.environ["KEYCLOAK_REALM_NAME"],
                                 client_secret_key=os.environ['KEYCLOAK_SECRET_KEY'])

keycloak_admin = KeycloakAdmin(server_url=os.environ['KEYCLOAK_URI'],
                               client_id=os.environ['KEYCLOAK_CLIENT_ID'],
                               realm_name=os.environ['KEYCLOAK_REALM_NAME'],
                               client_secret_key=os.environ['KEYCLOAK_SECRET_KEY'],
                               username=os.environ['KEYCLOAK_ADMIN'],
                               password=os.environ['KEYCLOAK_ADMIN_PASSWORD'],
                               auto_refresh_token=['get', 'post', 'put'])

client_id = keycloak_admin.get_client_id(os.environ['KEYCLOAK_CLIENT_ID'])


def setup_keycloak():
    # Configure realm
    keycloak_admin.update_realm("master", payload={
        "accessTokenLifespan": 1800,
        "editUsernameAllowed": True
    })

    # Configure roles
    roles = keycloak_admin.get_client_roles(client_id)
    role_names = [role['name'] for role in roles]
    if 'customer' not in role_names:
        keycloak_admin.create_client_role(client_id, {'name': 'customer', 'clientRole': True})
    if 'employee' not in role_names:
        keycloak_admin.create_client_role(client_id, {'name': 'employee', 'clientRole': True})
    if 'admin' not in role_names:
        keycloak_admin.create_client_role(client_id, {'name': 'admin', 'clientRole': True})


def register_customer(body):
    username = body['username']
    password = body['password']

    user_id = keycloak_admin.create_user({"email": username + "@gmail.com",
                                          "username": username,
                                          "enabled": True,
                                          "credentials": [{"value": password, "type": "password"}]}, exist_ok=True)
    # "credentials": [{"value": password, "type": "password", }]}, exist_ok=False)

    role = keycloak_admin.get_client_role(client_id=client_id, role_name="customer")
    keycloak_admin.assign_client_role(client_id=client_id, user_id=user_id, roles=[role])

    token = keycloak_openid.token(username, password)

    return get_token_response(token)


def auth(body):
    username = body['username']
    password = body['password']

    token = keycloak_openid.token(username, password)
    return get_token_response(token)


def register_employee(body):
    token = extract_token(request)

    if not contains_role('admin', token, CLIENT_NAME):
        abort(401)

    username = body['username']
    password = body['password']
    roles = body['roles']

    user_id = keycloak_admin.create_user({"email": username,
                                          "username": username,
                                          "enabled": True,
                                          "credentials": [{"value": password, "type": "password", }]}, exist_ok=False)

    for role in roles:
        r = keycloak_admin.get_client_role(client_id=client_id, role_name=role)
        keycloak_admin.assign_client_role(client_id=client_id, user_id=user_id, roles=[r])

    token = keycloak_openid.token(username, password)

    return get_token_response(token)


def create_role(body):
    token = extract_token(request)

    if not contains_role('admin', token, CLIENT_NAME):
        abort(401)
    keycloak_admin.create_client_role(client_id,
                                      {'name': body['role'], 'clientRole': True, "attributes": body['attributes']})
    return keycloak_admin.get_client_role(client_id, body['role'])


def user_contains_role(body):
    token = extract_token(request)
    return contains_role(body['role'], token, CLIENT_NAME)


def refresh_token(body):
    return keycloak_openid.refresh_token(body['refreshToken'])


def logout(body):
    keycloak_openid.logout(body['refreshToken'])


def contains_role(role, token, client):
    token_data = _token_info(token)
    print(token_data)
    if role in token_data['resource_access'][client]['roles']:
        return True

    return False


def token_info():
    token = extract_token(request)
    return _token_info(token)


def _token_info(token: str):
    KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
    options = {"verify_signature": True, "verify_aud": False, "verify_exp": True}
    return keycloak_openid.decode_token(token, key=KEYCLOAK_PUBLIC_KEY, options=options)


def user_info():
    token = extract_token(request)
    return _current_user_info(token)


def _current_user_info(token: str):
    data = _token_info(token)
    return _user_info(data['preferred_username'])


def _user_info(username: str):
    id = keycloak_admin.get_user_id(username)
    return keycloak_admin.get_user(id)


def get_token_response(token):
    return {"access_token": token['access_token'], "refresh_token": token['refresh_token'],
            "expires_in": token['expires_in'], "refresh_expires_in": token['refresh_expires_in']}


# TODO: Update User
def update_user(body):
    # clientRoles & realmRoles (but custom I guess with built-in set_role or w/e, we'll see)
    token = extract_token(request)
    user = _current_user_info(token)
    if not contains_role('admin', token, CLIENT_NAME) and user['id'] != body['id']:
        abort(401)

    id = body['id']
    del body['id']

    if 'password' in body.keys() and body['password'] is not None:
        keycloak_admin.set_user_password(id, body['password'], temporary=False)
        del body['password']

    keycloak_admin.update_user(id, payload=body)
    return keycloak_admin.get_user(id)


def extract_token(req):
    auth_header = req.headers['Authorization']
    token = auth_header.split(" ")[1]
    return token


def any_user_info(body):
    token = extract_token(request)
    if not contains_role('admin', token, CLIENT_NAME):
        abort(401)

    return _user_info(body['username'])


def delete_role(body):
    token = extract_token(request)
    if not contains_role('admin', token, CLIENT_NAME):
        abort(401)

    keycloak_admin.delete_client_role(client_id, body['role'])


def get_roles():
    return keycloak_admin.get_client_roles(client_id)


def get_role(body):
    return keycloak_admin.get_client_role(client_id, body['role'])


# TODO: Check token expiration


# TODO: Go through swagger-ui and find faulty definitions of request models
# TODO: Create guide for "import" and custom access token lifespan configuration and enabling update of usernames
# TODO: Separate contains_role and user_info in a separate package/project so other teams can copy/import it


connexion_app = connexion.App(__name__, specification_dir="./", options={'swagger_path': swagger_ui_3_path})
CORS(connexion_app.app)
app = connexion_app.app
connexion_app.add_api("api.yml")

if __name__ == '__main__':
    setup_keycloak()
    app.run(host="0.0.0.0")
