# `bff`: an OAuth2 Backend For Frontend

**What it shows**: `spring-addons-starter-oidc` configuring an OAuth2 **client** (`oauth2Login`) from properties: authorization-code with PKCE, RP-Initiated Logout, Back-Channel Logout, a CSRF token readable by JavaScript, and HTTP statuses a single-page application can actually consume. The gateway relays the access token kept in session to the [`resource-server`](../resource-server) sample.

Port `8080`. Servlet `spring-cloud-gateway-server-webmvc`.

## The pattern

The browser has a **session** on this gateway and never sees a token. The gateway runs the authorization-code flow, stores the tokens in session, and the `TokenRelay=` filter swaps the session cookie for the access token when routing `/bff/api/**` to the resource server. This is what [the OAuth2 BFF article](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2) describes, with the reactive gateway.

```
browser  --(session cookie)-->  bff :8080  --(Bearer access token)-->  resource-server :8081
                                    |
                                    +--(authorization-code, RP-Initiated & Back-Channel Logout)--> Keycloak :7080
```

## What you'd write without spring-addons

A `SecurityFilterChain` with `oauth2Login`, plus, for a JavaScript frontend: a `CookieCsrfTokenRepository.withHttpOnlyFalse()` and the `CsrfTokenRequestHandler` dance that makes the cookie actually written; an `AuthenticationEntryPoint` answering `401` instead of redirecting to login; `AuthenticationSuccessHandler`, `AuthenticationFailureHandler` and `LogoutSuccessHandler` returning 2xx with a `Location` header (so the SPA navigates itself instead of the browser following a cross-origin redirection inside a `fetch`); an `OAuth2AuthorizationRequestResolver` forcing PKCE and remembering where the frontend wants to land after login; a `GrantedAuthoritiesMapper` to get roles out of the ID token; and an `HttpSessionOAuth2AuthorizedClientRepository` so the tokens follow the session.

## What this sample contains instead

[`application.yml`](src/main/resources/application.yml), under `com.c4-soft.springaddons.oidc.client`:

| Property | Effect |
|---|---|
| `security-matchers: [/**]` | creates the client filter chain (sessions, CSRF, `oauth2Login`, logout). Without it, no client chain at all. |
| `client-uri` | public URI of this client: post-login, post-logout and callback URIs are resolved against it |
| `permit-all` | anonymous routes (`/`, `/login/**`, `/oauth2/**`, `/me`, the Back-Channel Logout endpoint) |
| `csrf: cookie-accessible-from-js` | CSRF token in a cookie the SPA can read, `X-XSRF-TOKEN` header |
| `oauth2-redirections.authentication-entry-point: UNAUTHORIZED` | `401` on protected routes instead of a `302` to login |
| `oauth2-redirections.pre-authorization-code: OK` | the "go to the authorization server" response is `200` + `Location`, for the SPA to navigate |
| `oauth2-redirections.rp-initiated-logout: ACCEPTED` | same, for logout |
| `post-login-redirect-path` / `post-logout-redirect-path` | defaults, overridable per request by the frontend with `X-POST-LOGIN-SUCCESS-URI` / `X-POST-LOGOUT-SUCCESS-URI` (checked against `post-login-allowed-uri-patterns` / `post-logout-allowed-uri-patterns` to prevent open redirects) |
| `pkce-forced: true` | PKCE for this confidential client (Spring enables it only for public ones) |
| `back-channel-logout.enabled: true` | Keycloak can end this session when the user logs out from another client |

Java code: [`BffApplication`](src/main/java/com/c4_soft/springaddons/samples/bff/BffApplication.java) (empty), [`MeController`](src/main/java/com/c4_soft/springaddons/samples/bff/MeController.java) (what the frontend needs about the current user) and [`LoginOptionsController`](src/main/java/com/c4_soft/springaddons/samples/bff/LoginOptionsController.java) (one login URI per `authorization_code` registration). No security configuration.

[`static/index.html`](src/main/resources/static/index.html) is a minimal stand-in for a SPA: plain `fetch()`, reading the CSRF cookie, and following the `Location` header of the 2xx OAuth2 responses with `window.location.href`.

## Tests

[`BffApplicationTest`](src/test/java/com/c4_soft/springaddons/samples/bff/BffApplicationTest.java) loads the whole application. An OAuth2 client fetches the OpenID configuration at startup, so WireMock stubs Keycloak (and, on the same port, the resource server) from [`src/test/resources/wiremock/keycloak`](src/test/resources/wiremock/keycloak). No login is ever performed: `@WithOidcLogin` puts an `OAuth2AuthenticationToken` with an `OidcUser` principal in the test security context, and `oauth2Client(...).accessToken(...)` puts an authorized client in the request for the `TokenRelay` filter to find.

It asserts the things the properties above are there for: the `401` on a protected route, the `200` + `Location` (with `code_challenge_method=S256`) starting the flow, the `202` + `Location` to the `end_session_endpoint` on logout, the non-HttpOnly CSRF cookie, and the Bearer token reaching the resource server.

## Run it

```bash
docker compose -f ../../infra/compose.yml up -d           # Keycloak on http://localhost:7080
(cd ../resource-server && ../../mvnw spring-boot:run) &   # the API on http://localhost:8081
../../mvnw -f pom.xml spring-boot:run
```
Open <http://localhost:8080> and log in as `brice` (granted with the `NICE` realm role) or `igor` (not granted). Both users come from the imported realm, with the passwords set in it; reset them from the Keycloak admin console (<http://localhost:7080/auth>, `admin` / `admin`) if needed. "Call the API" then hits `/bff/api/greetings/me`, which the gateway forwards to `http://localhost:8081/greetings/me` with the access token.

Two Keycloak client settings must match this configuration, and [`infra/import/spring-addons-realm.json`](../../infra/import/spring-addons-realm.json) already sets both on `spring-addons-user`:
- valid redirect URI: `http://localhost:8080/*`
- Back-Channel Logout URL: `http://host.docker.internal:8080/logout/connect/back-channel/spring-addons-user` (the path ends with the registration ID, so renaming the registration means changing it here too)
