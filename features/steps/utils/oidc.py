import jwt
import json
import requests
from urllib.parse import urljoin

class OIDC:

    def __init__(self, issuer):
        self.url = urljoin(issuer, "/.well-known/openid-configuration")
        r = requests.get(self.url)
        assert r.status_code == 200
        self.config = r.json()


    def get_jwks(self):
        url = self.config['jwks_uri']
        r = requests.get(url)
        return r.json()


    def register_client(self, name, grant_type, scopes, **kwargs):
        # kwargs e.g. { 'redirect_uris': ['http://localhost:5000/callback'] }
        url = self.config['registration_endpoint']
        headers = {
            'content-type': 'application/json'
        }

        json = {
            'client_name': name,
            'grant_types': [grant_type],
            'token_endpoint_auth_method': 'client_secret_post',
            'scope': scopes
        }
        json.update(kwargs)

        return requests.post(url, headers=headers, json=json)


    def register_protected_resource(self, name, scopes, **kwargs):
        url = urljoin(self.config['issuer'], '/resource')
        headers = {
            'content-type': 'application/json'
        }

        json = {
            "client_name": name,
            "token_endpoint_auth_method": "client_secret_post",
            "scope": scopes
        }
        json.update(kwargs)

        return requests.post(url, headers=headers, json=json)


    def get_token_via_client_credentials(self, client_id, client_secret, scopes=""):
        url = self.config['token_endpoint']
        headers = {
            'content-type': 'application/x-www-form-urlencoded'
        }

        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scopes
        }

        r = requests.post(url, headers=headers, data=data)
        return r


    def verify_token(self, token, jwk):
        # Find algorithm in jwk via kid mentioned in token's header
        kid = jwt.get_unverified_header(token)['kid']
        key = next(k for k in jwk['keys'] if k['kid'] == kid)
        key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        jwt.decode(token, key)


    def introspect_token(self, client_id, client_secret, token):
        url = self.config['introspection_endpoint']
        headers = {
            'content-type': 'application/x-www-form-urlencoded'
        }

        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "token": token
        }

        r = requests.post(url, headers=headers, data=data)
        return r
