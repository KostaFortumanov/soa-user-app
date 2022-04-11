from flask import Flask, request, abort
import connexion
from keycloak import KeycloakOpenID
from keycloak import KeycloakAdmin

# Configure client
keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/auth",
                                 client_id="account",
                                 realm_name="master",
                                 client_secret_key="uRQtLzpNKb9q1YmqTbqQDcXfy9JUUprj")

keycloak_admin = KeycloakAdmin(server_url="http://localhost:8080/auth", client_id='account',
                               client_secret_key="uRQtLzpNKb9q1YmqTbqQDcXfy9JUUprj", username='admin', password="kosta")

client_id = keycloak_admin.get_client_id('account')
# keycloak_admin.create_client_role(client_id, {'name': 'customer', 'clientRole': True})
# keycloak_admin.create_client_role(client_id, {'name': 'employee', 'clientRole': True})
# keycloak_admin.create_client_role(client_id, {'name': 'admin', 'clientRole': True})

# client_id = keycloak_admin.get_client_id('account')

#
# server_url="http://localhost:8080",
#                            username='admin',
#                            password='admin',
#                            realm_name="DogDayCare",
#                            user_realm_name="DogDayCare",
#                            client_secret_key="j6zDMVHHkAD46fY7uHOsR054ZCBnt4tn")

app = Flask(__name__)


def register_customer(register_body):
    username = register_body['username']
    password = register_body['password']

    user_id = keycloak_admin.create_user({"email": username,
                                          "username": username,
                                          "enabled": True,
                                          "credentials": [{"value": password, "type": "password", }]}, exist_ok=False)

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
    options = {"verify_signature": True, "verify_aud": True, "verify_exp": True}
    token_info = keycloak_openid.decode_token(token, key=KEYCLOAK_PUBLIC_KEY, options=options)

    if role in token_info['resource_access']['account']['roles']:
        return True

    return False


def user_info():
    auth_header = request.headers['Authorization']
    token = auth_header.split(" ")[1]
    KEYCLOAK_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + keycloak_openid.public_key() + "\n-----END PUBLIC KEY-----"
    options = {"verify_signature": True, "verify_aud": True, "verify_exp": True}
    return keycloak_openid.decode_token(token, key=KEYCLOAK_PUBLIC_KEY, options=options)


def get_token_response(token):
    return {"access_token": token['access_token'], "refresh_token": token['refresh_token'],
            "expires_in": token['expires_in'], "refresh_expires_in": token['refresh_expires_in']}


connexion_app = connexion.App(__name__, specification_dir="./")
app = connexion_app.app
connexion_app.add_api("api.yml")

if __name__ == '__main__':
    app.run()

    # return keycloak_admin.get_realm_roles()
    # token = keycloak_openid.token(auth_body['username'], auth_body['password'])
    # userinfo = keycloak_openid.userinfo('eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJYTWo4YlpmSUplQTJzQVc4VU1hakgtSnRRcGZ3Tk05NXVaVEFoT0x4RF9NIn0.eyJleHAiOjE2NDk3MDYwMTcsImlhdCI6MTY0OTcwNTk1NywianRpIjoiNmVhY2U5MjMtZjczZS00NjI3LWFkY2YtOTdmM2RiMjM1YTZmIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJzdWIiOiJiODEwMTYyZi04MmM0LTRiNDItOGMxYS02NmYyMzBjZTZkYjUiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhY2NvdW50Iiwic2Vzc2lvbl9zdGF0ZSI6ImZkNzVmNjc5LTk1ZmMtNGE2MS04NWQ4LTZmZTRjYTlkMDIxOCIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1tYXN0ZXIiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwic2lkIjoiZmQ3NWY2NzktOTVmYy00YTYxLTg1ZDgtNmZlNGNhOWQwMjE4IiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiRXhhbXBsZSBFeGFtcGxlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiZXhhbXBsZUBleGFtcGxlLmNvbSIsImdpdmVuX25hbWUiOiJFeGFtcGxlIiwiZmFtaWx5X25hbWUiOiJFeGFtcGxlIiwiZW1haWwiOiJleGFtcGxlQGV4YW1wbGUuY29tIn0.pSOsj_3uh34j2nsGx2I7yVcbPF3IJ8kEmKipa1F9c6njRC-yJpy_kgameX4xYY7bPvX0-9tusDMtaKgtNXKNhUn0Yqpy4BLIm71DtSN4QfXWgza3F9MA8Lnea7SzlpbxDLPp2gWfflaeoFfCFgBNOVXtsJvM70XoYXOWZQ1XlKl82zA4VcmFB-yl5IxRktN3Miq6TkoU2kDocfy-bLtoZ7NxdUkThyEkkqcLeBiBbrow-i_OoeizmAVYsc-r8Ruh8YGf7CjiEMTe_ij9eaAW0KYEB1VsCGs4lobkLp14b3FBfcf6wzKeLzn-u1UF8sm3u-1aiUmXWB9F3eGxIcvUmQ')
    # user_id_keycloak = keycloak_admin.get_user_id("example@example.com")
    # keycloak_admin.create_client_role('4a0d1c93-3c71-44b4-8ded-876991a167d5', {'name': 'test14', 'clientRole': True})
    # role = keycloak_admin.get_client_role(client_id="4a0d1c93-3c71-44b4-8ded-876991a167d5",
    #                                       role_name="test14")  # print(role_id)
    # print(role)
    # # keycloak_admin.assign_client_role(client_id="4a0d1c93-3c71-44b4-8ded-876991a167d5", user_id="b810162f-82c4-4b42-8c1a-66f230ce6db5", roles="405a7eac-ab71-4c1a-8d13-ef0a87e31964")
    # keycloak_admin.assign_client_role(client_id="4a0d1c93-3c71-44b4-8ded-876991a167d5",
    #                                   user_id="b810162f-82c4-4b42-8c1a-66f230ce6db5", roles=[role])
    # return keycloak_admin.get_client_roles_of_user(user_id="b810162f-82c4-4b42-8c1a-66f230ce6db5",
    #                                                client_id="4a0d1c93-3c71-44b4-8ded-876991a167d5")
    # # return keycloak_admin.get_client_id("account")
    # return user_id_keycloak
