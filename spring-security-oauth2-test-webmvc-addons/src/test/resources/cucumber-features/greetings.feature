Feature: Testing a secured REST API with @WithMockSomething
  Authenticated users should be able to submit GET greetings

  Scenario: Unauthorized users shouldn't be greeted
    When unauthenticated users want to get greeting
    Then it is redirected to login

  Scenario: Authorized users should be greeted
    When authenticated users want to get greeting
    Then a greeting is returned