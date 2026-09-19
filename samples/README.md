# spring-addons samples

Five runnable Spring Boot applications, each focused on one thing this repo's starters make easy. All of them work against the same Keycloak instance, started with [`../infra/compose.yml`](../infra/compose.yml).

| Module | Port | What it demonstrates |
|---|---|---|
| [`resource-server`](resource-server) | 8081 | A REST API secured with JWT access tokens: `spring-addons-starter-oidc` replaces the whole security Java configuration with properties (several trusted issuers, authorities from any claim, CORS, public routes, `401` instead of a login redirect), and `spring-addons-starter-oidc-test` puts real `Authentication` instances in the test security context from JSON claim-sets. An `introspection` profile switches token validation to the authorization server without touching a line of code. |
| [`resource-server-reactive`](resource-server-reactive) | 8082 | The same application in WebFlux, to show that properties and test annotations are unchanged: only the Spring types differ. |
| [`bff`](bff) | 8080 | An OAuth2 **B**ackend **F**or **F**rontend: a servlet `spring-cloud-gateway` with `oauth2Login`, relaying the access token in session to the resource server. Authorization-code with PKCE, RP-Initiated and Back-Channel Logout, CSRF cookie for JavaScript, and 2xx statuses a single-page application can consume, all from properties. |
| [`rest-client`](rest-client) | 8083 | A resource server calling other APIs with `RestClient` beans auto-configured by `spring-addons-starter-rest`: Bearer forwarded from the security context, Bearer from a `client_credentials` registration, and `@ImportHttpServices` proxies backed by one of those clients. |
| [`client-and-resource-server`](client-and-resource-server) | 8084 | One application with **both** chains: a Thymeleaf UI secured with sessions (`oauth2Login`, redirected to login) and a REST API secured with access tokens (stateless, `401`). Shows what `security-matchers` decides, and the UI calling its own API with the token kept in session. |

Each module has its own README explaining what the configuration replaces, what the tests assert, and how to run it.

## Running them

```bash
docker compose -f ../infra/compose.yml up -d
```
This starts Keycloak on <http://localhost:7080/auth> (admin console: `admin` / `admin`) with the `spring-addons` realm imported from [`../infra/import/spring-addons-realm.json`](../infra/import/spring-addons-realm.json):
- users `brice` (granted with the `NICE` realm role) and `igor` (not granted). Passwords are those stored in the realm export; reset them from the admin console if needed.
- a confidential client `spring-addons-user` (secret `secret`) for the authorization-code flow of `bff` and `client-and-resource-server`
- a confidential client `spring-addons-m2m` (secret `secret`) whose service account is granted `view-users`, for the `client_credentials` flow of `rest-client`

Then, from this directory:
```bash
../mvnw install                       # build all five modules and run their tests
../mvnw -f bff spring-boot:run        # or any other module
```
The tests need neither Keycloak nor Docker: token decoding is mocked and the consumed APIs are stubbed with WireMock. Only running the applications does.

## Reading order

If you are new to these libraries, start with [`resource-server`](resource-server): it is the smallest, and the properties it uses (trusted issuers, authorities mapping) are shared by every other module. Then pick the one matching what you have to build.

If you are not sure whether your application should be an OAuth2 **client** (sessions, login, logout: the `bff` sample) or an OAuth2 **resource server** (access tokens, no session, no login: the `resource-server` sample), read the *OAuth2 Resource Servers* and *OAuth2 Clients* sections of the [`spring-addons-starter-oidc` README](../spring-addons-starter-oidc/README.MD) first. Configuring the wrong one is the most common and the most expensive mistake. If the answer is "both", [`client-and-resource-server`](client-and-resource-server) shows how the two coexist.

## Conventions shared by the samples

- **No security filter chain is ever written.** When a default has to change, the sample replaces a single `@ConditionalOnMissingBean` bean (see the authentication converters in `resource-server`) rather than the whole chain.
- **Access control lives next to the code it protects**: `@PreAuthorize` on `@RestController` and `@Service` methods, with only the anonymous routes listed in properties.
- **Tests never decode a real token and never call an authorization server.** `@WithJwt("brice.json")` loads a claim-set from the test classpath and runs it through the application's own authentication converter, so the username, the authorities and the `Authentication` type are the ones the application would build at runtime.
- **Test users are the realm users**: `brice.json` and `igor.json` mirror what Keycloak puts in an access token for `brice` and `igor`.
