from behave import *
import requests
from utils.oidc import OIDC


@given("an OIDC server at {issuer}")
def step_impl(context, issuer):
    context.oidc = OIDC(issuer)


@when("we request its configuration URL")
def step_impl(context):
    url = "{}/.well-known/openid-configuration".format(context.issuer)
    context.response = requests.get(url)


@then("the http status code should be {code:d}")
def step_impl(context, code):
    assert code == context.response.status_code, context.response.status_code


@then("the response should be valid JSON")
def step_impl(context):
    context.response.json()


@when("we register a client with {name}, {grant_type}, {redirect_uri}, {scopes}")
def step_impl(context, name, grant_type, redirect_uri, scopes):
    # Leave out redirect_uri if it is None
    if redirect_uri == 'None':
        options = {}
    else:
        options = {'redirect_uris': [redirect_uri]}
    context.response = context.oidc.register_client(
        name, grant_type, scopes, **options)


@given(u'a client registered to use client_credentials and scopes {scopes}')
def step_impl(context, scopes):
    options = {
        'name': 'Test client',
        'grant_type': 'client_credentials',
        'scopes': scopes
    }
    r = context.oidc.register_client(**options)
    assert r.status_code == 201, r.status_code
    context.client_info = r.json()


@given(u'a protected resource registered to use scopes {scopes}')
def step_impl(context, scopes):
    options = {
        'name': 'Test resource',
        'scopes': scopes
    }
    r = context.oidc.register_protected_resource(**options)
    assert r.status_code == 201, r.status_code
    context.protected_resource_info = r.json()


@given(u'the issuer\'s JWKs')
def step_impl(context):
    context.jwk = context.oidc.get_jwks()


@when(u'we request a token via client_credentials with scopes {scopes}')
def step_impl(context, scopes):
    client_id = context.client_info['client_id']
    client_secret = context.client_info['client_secret']

    r = context.oidc.get_token_via_client_credentials(
        client_id, client_secret, scopes)
    context.response = r


@then(u'the {token_key} should be a valid JWT')
def step_impl(context, token_key):
    token = context.response.json()[token_key]
    jwk = context.jwk
    context.oidc.verify_token(token, jwk)


@when(u'we remember the access_token')
def step_impl(context):
    context.access_token = context.response.json()['access_token']


@when(u'the {client_type} introspects the {token_type}')
def step_impl(context, client_type, token_type):
    if client_type == 'client':
        info = context.client_info
    elif client_type == 'protected resource':
        info = context.protected_resource_info

    if token_type == 'access_token':
        token = context.access_token

    client_id = info['client_id']
    client_secret = info['client_secret']
    context.response = context.oidc.introspect_token(
        client_id, client_secret, token)


@then(u'the response should indicate the allowed scopes are {scopes}')
def step_impl(context, scopes):
    json = context.response.json()
    # Scopes can be returned in any order
    allowed_scopes = json['scope'].split(" ")
    expected_scopes = scopes.split(" ")
    assert set(allowed_scopes) == set(expected_scopes)
