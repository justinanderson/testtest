Feature: Expected OIDC server functionality

  Background:
    Given an OIDC server at http://localhost:8080/

  Scenario Outline: Dynamically register a client
    When we register a client with <name>, <grant_type>, <redirect_uri>, <scopes>
    Then the http status code should be 201
     And the response should be valid JSON
  
    Examples:
      | name   | grant_type         | redirect_uri                   | scopes               |
      | one    | client_credentials | None                           | test1 test2 test3    |
      | two    | authorization_code | http://localhost:5000/callback | openid profile       |
      | three  | implicit           | http://localhost:5000/callback | test2                |

  Scenario: Acquire an access_token as one client and introspect it as a
            protected resource, seeing only the intersection of authorized and
            registered scopes.
    Given a client registered to use client_credentials and scopes test1 test2
      And a protected resource registered to use scopes test2 test3
      And the issuer's JWKs
     When we request a token via client_credentials with scopes test1 test2
     Then the http status code should be 200
      And the response should be valid JSON
      And the access_token should be a valid JWT
     When we remember the access_token
      And the client introspects the access_token
     Then the http status code should be 403
     When the protected resource introspects the access_token
     Then the response should indicate the allowed scopes are test2
