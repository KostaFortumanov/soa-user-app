from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from flask import Flask, request, abort
import connexion
from flask_cors import CORS
from keycloak import KeycloakOpenID, KeycloakGetError
from keycloak import KeycloakAdmin
from swagger_ui_bundle import swagger_ui_3_path

import os

# Setup
from middleware.SOAKeycloakAdmin import SOAKeycloakAdmin

load_dotenv()

CLIENT_NAME = "soa-account"

keycloak_openid = KeycloakOpenID(server_url=os.environ['KEYCLOAK_URI'],
                                 client_id=os.environ['KEYCLOAK_CLIENT_ID'],
                                 realm_name=os.environ["KEYCLOAK_REALM_NAME"],
                                 client_secret_key=os.environ['KEYCLOAK_SECRET_KEY'])

keycloak_admin = SOAKeycloakAdmin(server_url=os.environ['KEYCLOAK_URI'],
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
        "ssoSessionIdleTimeout": 3600,
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


# Utility

def _token_info(token: str):
    KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
    options = {"verify_signature": True, "verify_aud": False, "verify_exp": True}
    return keycloak_openid.decode_token(token, key=KEYCLOAK_PUBLIC_KEY, options=options)


def _current_user_info(token: str):
    data = _token_info(token)
    return _user_info(data['preferred_username'])


def _user_info(username: str):
    id = keycloak_admin.get_user_id(username)
    return keycloak_admin.get_user(id)


def _extract_token(req):
    auth_header = req.headers['Authorization']
    token = auth_header.split(" ")[1]
    return token


def _extract_roles(data, client):
    return data['resource_access'][client]['roles']


def _transform_token(token):
    return {"access_token": token['access_token'], "refresh_token": token['refresh_token'],
            "expires_in": token['expires_in'], "refresh_expires_in": token['refresh_expires_in']}


# /auth

def auth(body):
    username = body['username']
    password = body['password']

    token = keycloak_openid.token(username, password)
    return _transform_token(token)


def logout(body):
    keycloak_openid.logout(body['refreshToken'])


def refresh_token(body):
    return keycloak_openid.refresh_token(body['refreshToken'])


def token_info():
    token = _extract_token(request)
    return _token_info(token)


def check_token_validity():
    token = _extract_token(request)
    try:
        keycloak_openid.userinfo(token)
        return True
    except KeycloakGetError:
        return False


# /user

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

    return _transform_token(token)


def register_employee(body):
    token = _extract_token(request)

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

    return _transform_token(token)


def user_info():
    token = _extract_token(request)
    return _current_user_info(token)


def any_user_info(body):
    token = _extract_token(request)
    if not contains_role('admin', token, CLIENT_NAME):
        abort(401)

    return _user_info(body['username'])


def simple_user_info():
    token = _extract_token(request)
    return keycloak_openid.userinfo(token)


def complex_user_info():
    token = _extract_token(request)
    user_info_data = _current_user_info(token)
    token_info_data = _token_info(token)
    user_info_data.update(token_info_data)
    return user_info_data


def update_user(body):
    # clientRoles & realmRoles (but custom I guess with built-in set_role or w/e, we'll see)
    token = _extract_token(request)
    user = _current_user_info(token)
    is_admin = contains_role('admin', token, CLIENT_NAME)
    if not is_admin and user['id'] != body['id']:
        abort(401)

    id = body['id']
    del body['id']

    if 'clientRoles' in body.keys():
        del body['clientRoles']
    if 'realmRoles' in body.keys():
        del body['realmRoles']

    if 'roles' in body.keys():
        if is_admin:
            # Un assign all
            assigned_roles = [keycloak_admin.get_client_role(client_id, role) for role in
                              _extract_roles(_token_info(token), CLIENT_NAME)]
            keycloak_admin.unassign_client_role(user['id'], client_id, assigned_roles)

            # Assign new
            roles = [keycloak_admin.get_client_role(client_id, role) for role in body['roles']]
            keycloak_admin.assign_client_role(user['id'], client_id, roles)
        del body['roles']

    if 'password' in body.keys():
        if body['password'] is not None:
            keycloak_admin.set_user_password(id, body['password'], temporary=False)
        del body['password']

    keycloak_admin.update_user(id, payload=body)
    return keycloak_admin.get_user(id)


def delete_user(body):
    token = _extract_token(request)
    user = _current_user_info(token)
    if not contains_role('admin', token, CLIENT_NAME) and user['id'] != body['id']:
        abort(401)

    keycloak_admin.delete_user(user['id'])


# /role

def create_role(body):
    token = _extract_token(request)

    if not contains_role('admin', token, CLIENT_NAME):
        abort(401)
    keycloak_admin.create_client_role(client_id,
                                      {'name': body['role'], 'clientRole': True, "attributes": body['attributes']})
    return keycloak_admin.get_client_role(client_id, body['role'])


def get_role(body):
    return keycloak_admin.get_client_role(client_id, body['role'])


def get_roles():
    return keycloak_admin.get_client_roles(client_id)


def delete_role(body):
    token = _extract_token(request)
    if not contains_role('admin', token, CLIENT_NAME):
        abort(401)

    keycloak_admin.delete_client_role(client_id, body['role'])


def update_role(body):
    token = _extract_token(request)
    if not contains_role("admin", token, CLIENT_NAME):
        abort(401)

    role = keycloak_admin.get_client_role(client_id, body['role'])
    role['attributes'] = body['attributes']
    try:
        keycloak_admin.update_role(role)
        return keycloak_admin.get_client_role(client_id, role['name'])
    except KeycloakGetError:
        abort(401, "Role attributes can only be lists!")


def user_contains_role(body):
    token = _extract_token(request)
    return contains_role(body['role'], token, CLIENT_NAME)


def contains_role(role, token, client):
    token_data = _token_info(token)
    if role in _extract_roles(token_data, client):
        return True

    return False


# TODO: Create guide for import
# TODO: Separate contains_role and user_info in a separate package/project so other teams can copy/import it
# TODO: Better description for status codes, and make status codes more precise in general

connexion_app = connexion.App(__name__, specification_dir="./", options={'swagger_path': swagger_ui_3_path})
CORS(connexion_app.app)
app = connexion_app.app
connexion_app.add_api("api.yml")

if __name__ == '__main__':
    setup_keycloak()
    app.run(host="0.0.0.0")
