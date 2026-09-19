# `rest-client`: calling other APIs with auto-configured REST clients

**What it shows**: `spring-addons-starter-rest` turning `com.c4-soft.springaddons.rest` properties into ready-to-inject `RestClient` beans, with the two OAuth2 authorization strategies a resource server needs, and backing `@ImportHttpServices` proxies with one of those clients.

Port `8083`. This application is a resource server (secured with access tokens, like [`resource-server`](../resource-server)) which is itself a **client** of two other APIs.

## The two ways of authorizing an outgoing request

| Scenario | Property | What is sent |
|---|---|---|
| Call another API **on behalf of the current user** | `authorization.oauth2.forward-bearer: true` | the access token which authorized the incoming request, taken from the security context (only possible in a resource server) |
| Call an API **as the application itself** (no user) | `authorization.oauth2.oauth2-registration-id: <id>` | a token obtained with that registration — here a `client_credentials` one, cached and reused across requests |

There is also `authorization.basic` (username / password or encoded credentials) and static `headers` for API keys.

## What you'd write without spring-addons

For the forwarded Bearer: a `ClientHttpRequestInterceptor` reading the `Authentication` from the `SecurityContextHolder`, unwrapping the right token type, and skipping anonymous requests. For the `client_credentials` one: an `OAuth2AuthorizedClientManager` wired to a `ClientRegistrationRepository` and an `OAuth2AuthorizedClientService` (**not** the request-scoped repository Spring Boot defaults to in a web application, or a token is fetched for every call), plus an `OAuth2ClientHttpRequestInterceptor` with a fixed registration ID and a principal resolver tolerating the absence of a user. Then, per client, base URL, timeouts, headers, and a `ClientHttpRequestFactory` for proxy or SSL settings.

## What this sample contains instead

[`application.yml`](src/main/resources/application.yml):
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          greetings-client:                 # exposes a RestClient bean named greetingsClient
            base-url: ${greetings-api}
            authorization:
              oauth2:
                forward-bearer: true
            http:
              connect-timeout-millis: 2000
              read-timeout-millis: 5000
          keycloak-admin-client:            # exposes a RestClient bean named keycloakAdminClient
            base-url: ${keycloak-admin-api}
            authorization:
              oauth2:
                oauth2-registration-id: keycloak-admin   # a client_credentials registration
            headers:
              Accept:
                - application/json
        group:
          keycloak-admin-group:             # backs the @ImportHttpServices group with that client
            client: keycloak-admin-client
```
The bean name is the camelCase of the property key. `expose-builder: true` would expose a `RestClient.Builder` instead, to finish its configuration in Java. Other properties cover HTTP proxies (also picked up from `HTTP_PROXY` / `NO_PROXY`), SSL bundles, disabling certificate validation, and the underlying HTTP client implementation.

Java code:
- [`ProxyController`](src/main/java/com/c4_soft/springaddons/samples/restclient/ProxyController.java) injects the `greetingsClient` bean by name and the `@HttpExchange` proxy.
- [`HttpServicesConfiguration`](src/main/java/com/c4_soft/springaddons/samples/restclient/HttpServicesConfiguration.java) registers the proxies of the `keycloak-admin-group` group with `@ImportHttpServices` (Spring Framework 7). The group takes the base URL, headers, authorization and request factory of the client it references. In a real project, [`KeycloakUsersApi`](src/main/java/com/c4_soft/springaddons/samples/restclient/KeycloakUsersApi.java) would be generated from the consumed API's OpenAPI spec by the `openapi-generator-maven-plugin`.

No `RestClient` bean is defined anywhere in this application.

> [!NOTE]
> `spring-addons-starter-rest` declares `spring-boot-restclient` as optional, so the application must bring `spring-boot-starter-restclient` itself (or `spring-boot-starter-webclient` for `WebClient` beans).

## Tests

[`RestClientApplicationTest`](src/test/java/com/c4_soft/springaddons/samples/restclient/RestClientApplicationTest.java) stubs both consumed APIs and Keycloak's token endpoint with WireMock, then asserts what the clients actually put on the wire: `/greetings/me` receives the very Bearer of the incoming request (`@WithJwt(file = "brice.json", bearerString = "brice-access-token")`), while the Keycloak admin API receives the token returned by the stubbed `client_credentials` flow.

It imports only `AuthenticationFactoriesTestConf` (the factories behind `@WithJwt`) rather than `AddonsWebmvcTestConf`, which would replace the `ClientRegistrationRepository` with a mock and break the `client_credentials` flow.

## Run it

```bash
docker compose -f ../../infra/compose.yml up -d           # Keycloak on http://localhost:7080
(cd ../resource-server && ../../mvnw spring-boot:run) &   # the API on http://localhost:8081
../../mvnw -f pom.xml spring-boot:run
```
Get an access token (see the [`resource-server` README](../resource-server/README.md#run-it)) and:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8083/relayed-greeting   # token forwarded
curl -H "Authorization: Bearer $TOKEN" http://localhost:8083/users              # needs NICE
```
`/users` calls Keycloak's admin API with the `spring-addons-m2m` service account, to which the imported realm grants the `view-users` and `query-users` roles of the `realm-management` client.
