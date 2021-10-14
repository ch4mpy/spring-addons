Feature: Testing a secured REST API with @WithMockSomething
  Authenticated users should be able to submit GET greetings

  Scenario: Authorized users should be greeted
    Given the following user roles:
      | ROLE_user   |
      | ROLE_TESTER |
    When a get request is sent to greeting endpoint
    Then a greeting is returned

  Scenario: Unauthorized users shouldn't be greeted
    Given user is not authenticated
    When a get request is sent to greeting endpoint
    Then user is redirected to login