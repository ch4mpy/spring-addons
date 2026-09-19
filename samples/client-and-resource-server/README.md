# `client-and-resource-server`: two filter chains in one application

**What it shows**: one application exposing both a UI secured with **sessions** (OAuth2 client, `oauth2Login`) and a REST API secured with **access tokens** (OAuth2 resource server), which `spring-addons-starter-oidc` builds as two ordered filter chains from properties alone.

Port `8084`.

## Why two chains

The two have irreconcilable requirements. A UI consumed by a browser is authorized by a session cookie, so it needs a session, CSRF protection, and a redirection to login when the user is not authenticated. A REST API is authorized by a Bearer token, so it must stay stateless, has no use for CSRF protection, and must answer `401` rather than redirect. That cannot be a single `SecurityFilterChain`, and this is the scenario where the `security-matchers` property earns its place:

| | client chain | resource server chain |
|---|---|---|
| Order | `LOWEST_PRECEDENCE - 1` | `LOWEST_PRECEDENCE` |
| Intercepts | exactly `com.c4-soft.springaddons.oidc.client.security-matchers` | everything else (no matcher: it is the default) |
| Session | yes | no |
| CSRF | yes | disabled |
| Unauthorized | `302` to login | `401` |
| Authentication | `OAuth2AuthenticationToken` (from `oauth2Login`) | `JwtAuthenticationToken` (from the access token) |

Requests are offered to the chains in order, and **the first matching chain wins**: `/ui/greeting` is listed in the client matchers, `/api/greetings/me` is not, so it falls through.

## The configuration

In [`application.yml`](src/main/resources/application.yml):
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:                              # shared: authorities and username mapping for both chains
          - iss: ${keycloak-issuer}
            username-claim: preferred_username
            authorities:
              - path: $.realm_access.roles
        client:
          security-matchers:              # what the client chain intercepts
            - /
            - /ui/**
            - /login/**
            - /oauth2/**
            - /logout
          permit-all: [ /, /login/**, /oauth2/** ]
          client-uri: ${client-uri}
          post-login-redirect-path: /ui/greeting
          pkce-forced: true
        resourceserver:
          permit-all:                     # applies to what the client chain did not match
            - /api/greetings/public
```
Note that `ops` is shared: the client chain maps the **ID token** claims to authorities with the same rules the resource server chain applies to the **access token** claims, so a user has the same roles on both sides.

Adding a third authorization mechanism (Basic auth, an API key) means adding a chain of your own with `@Order(Ordered.LOWEST_PRECEDENCE - 2)` or higher and a strict `securityMatcher`; both auto-configured chains keep working below it.

## The UI calling its own API

[`UiController`](src/main/java/com/c4_soft/springaddons/samples/clientandresourceserver/ui/UiController.java) renders Thymeleaf pages from a session, but the data comes from the REST API, which only accepts access tokens. The bridge is a REST client auto-configured by `spring-addons-starter-rest` with `oauth2-registration-id: spring-addons-user`: it authorizes its requests with the token the client chain keeps in session for that registration.

```yaml
com.c4-soft.springaddons.rest.client.greetings-api-client:
  base-url: ${client-uri}/api
  authorization.oauth2.oauth2-registration-id: spring-addons-user
```
[`UiConfiguration`](src/main/java/com/c4_soft/springaddons/samples/clientandresourceserver/ui/UiConfiguration.java) wraps that client in an `@HttpExchange` proxy. The request leaves the application as an ordinary HTTP call with a Bearer header and comes back in through the resource server chain, exactly as a separate service would call it.

## Tests

[`TwoFilterChainsTest`](src/test/java/com/c4_soft/springaddons/samples/clientandresourceserver/TwoFilterChainsTest.java) asserts the routing between the chains, which is the whole point of the module: the same anonymous request gets a `302` to login on `/ui/**` and a `401` on `/api/**`. It uses the annotation matching each chain, `@WithOidcLogin` for the UI and `@WithJwt` for the API, and checks that a `JwtAuthenticationToken` does not open the UI.

`@WithOidcLogin(nameAttributeKey = "preferred_username")` mirrors `spring.security.oauth2.client.provider.keycloak.user-name-attribute`; without it, `Authentication#getName()` is the `sub` claim.

## Run it

```bash
docker compose -f ../../infra/compose.yml up -d
../../mvnw -f pom.xml spring-boot:run
```
Open <http://localhost:8084> and log in as `brice` or `igor`. The greeting page is rendered from the session but its content comes from the REST API. Meanwhile:
```bash
curl http://localhost:8084/api/greetings/public   # 200, anonymous
curl -i http://localhost:8084/api/greetings/me    # 401, no redirection to login
```
The imported realm already allows `http://localhost:8084/*` as a redirect URI for the `spring-addons-user` client, alongside the `http://localhost:8080/*` the [`bff`](../bff) sample uses.
