---
title: An OAuth2 BFF, end to end
parent: Articles
nav_order: 1
description: "What a Backend For Frontend actually requires beyond the diagram: sessions instead of tokens in the browser, a CSRF cookie JavaScript can read, 2xx instead of 3xx on OAuth2 redirections, PKCE on a confidential client, RP-Initiated and Back-Channel Logout."
---

# An OAuth2 BFF for a single-page application, end to end
{: .no_toc }

1. TOC
{:toc}

## The one-sentence version, and why it is not enough

A Backend For Frontend is a server-side OAuth2 client sitting between a browser application and the APIs it consumes. The browser holds a session cookie and never sees a token. The BFF runs the authorization code flow, keeps the tokens in its session store, and swaps the cookie for the access token when it forwards a call:

```
browser  --(session cookie)-->  bff :8080  --(Bearer access token)-->  resource-server :8081
                                    |
                                    +--(authorization code, RP-Initiated & Back-Channel Logout)--> Keycloak :7080
```

Everybody agrees on that diagram. It says nothing about the part which actually costs time, which is that a single-page application is not a browser doing navigations. It is JavaScript doing `fetch`, and every OAuth2 behaviour Spring Security defaults to was designed for the former.

This is the rundown of what changes, with the properties which set it in a Spring Boot application using `spring-addons-starter-oidc`, and the hand-written equivalent for each one. The whole thing is a runnable application in [the `bff` sample](https://github.com/ch4mpy/spring-addons/tree/master/samples/bff), a servlet `spring-cloud-gateway` whose only Java code is three controllers and no security configuration at all.

## Why the tokens belong on the server

The alternative is a public client in the browser, which is still what most tutorials show. Three things make it the weaker option, and only the first is usually mentioned.

A token in `localStorage` or in a JavaScript variable is readable by any script the page ends up running, which includes every transitive npm dependency. A session cookie marked `HttpOnly` is not. That is the argument everybody knows.

The second is that a browser client cannot keep a secret, so it cannot be a confidential client, so it cannot use the `refresh_token` grant safely, so its access tokens either live long enough to be dangerous or expire often enough to be annoying. On the server, the refresh token never leaves the JVM.

The third is operational: with a BFF, logging a user out is a server-side decision. The session is destroyed, and the tokens go with it. In the browser, revoking is asking the frontend nicely.

The cost is real and worth stating: the BFF is a stateful component in front of stateless APIs, so it needs a session store and it needs to be part of the deployment topology. That is the trade.

## What the browser needs, behaviour by behaviour

### An unauthenticated call must return 401, not a login page

Spring Security's default `AuthenticationEntryPoint` for `oauth2Login` redirects to the authorization server. In a navigation that is exactly right. Inside a `fetch`, the browser follows the redirection transparently, the login page comes back with CORS headers that do not allow it, and the frontend sees an opaque network error instead of "you are not logged in".

The frontend has to be told, in a status it can read, that a session is missing. Then it decides whether to start a login flow, show a "sign in" button, or retry.

```yaml
oauth2-redirections:
  authentication-entry-point: UNAUTHORIZED
```

By hand: an `AuthenticationEntryPoint` returning `401`, registered on the chain.

### Starting the flow must be a 2xx with a Location header

The same problem, one step later. When the frontend does decide to log in, it calls `/oauth2/authorization/<registration>`. Spring answers `302` to the authorization server. Inside a `fetch`, the browser follows that redirection too, cross-origin, and fails.

The fix is counter-intuitive and is the heart of the pattern: answer `200` with the `Location` header still set, and let the JavaScript navigate itself with `window.location.href`. The browser leaves the application, the user authenticates, and comes back to the callback URI with a session.

```yaml
oauth2-redirections:
  pre-authorization-code: OK
  rp-initiated-logout: ACCEPTED
```

By hand: an `AuthenticationSuccessHandler`, an `AuthenticationFailureHandler`, a `LogoutSuccessHandler` and a redirect strategy for the authorization request, each writing the status and the header rather than delegating to the default redirect.

### The CSRF token must be readable by JavaScript

A session-based application needs CSRF protection, and Spring Security's default stores the token in the session, which the frontend cannot read. The `CookieCsrfTokenRepository.withHttpOnlyFalse()` form exists for this, and on its own it is not enough: since Spring Security 6, the deferred token loading means the cookie is often not written unless a `CsrfTokenRequestHandler` forces the token to be resolved. This is the single most common reason a BFF returns `403` on every `POST` and nobody knows why.

```yaml
csrf: cookie-accessible-from-js
```

The frontend then reads the `XSRF-TOKEN` cookie and sends it back in `X-XSRF-TOKEN`.

### PKCE, on a confidential client

Spring Security enables PKCE automatically for public clients only, on the reasonable ground that a confidential client already authenticates with a secret. In a BFF, forcing it anyway costs nothing and closes authorization code injection at the redirect URI.

```yaml
pkce-forced: true
```

By hand: an `OAuth2AuthorizationRequestResolver` wrapping the default one and calling `OAuth2AuthorizationRequestCustomizers.withPkce()`.

### Post-login and post-logout destinations, without an open redirect

A single-page application knows where the user was when the session expired, and wants to come back there. That destination has to travel through a flow which leaves the application entirely, and it has to be validated on the way back, or the BFF becomes an open redirect.

```yaml
client-uri: http://localhost:8080
post-login-redirect-path: /
post-logout-redirect-path: /
```

Per request, the frontend overrides them with `X-POST-LOGIN-SUCCESS-URI` and `X-POST-LOGOUT-SUCCESS-URI`, checked against `post-login-allowed-uri-patterns` and `post-logout-allowed-uri-patterns`, which default to any path on this server.

### Logout, in both directions

RP-Initiated Logout is the specified way for a client to end a session at the authorization server. Spring Security implements it, and then there is reality: Auth0 and Amazon Cognito do not implement the specification, each in its own way, so a client which follows the standard fails against both. That is a URI-building problem, and building the right URI per provider is what `logoutRequestUriBuilder` does.

Back-Channel Logout is the other direction: the user signs out from a different application in the same SSO realm, and the authorization server notifies this client so it can destroy its session. It needs an endpoint, a session registry mapping provider sessions to server sessions, and it needs that endpoint to be anonymous, because the request comes from the authorization server and not from a user-agent with a cookie.

```yaml
permit-all:
  - /logout/connect/back-channel/spring-addons-user
back-channel-logout:
  enabled: true
```

The path ends with the registration ID, which is also in the login URI and the callback URI. Renaming a registration means changing it in the authorization server too, which is worth knowing before a production rename.

## Relaying the token

None of the above is specific to a gateway. What makes a `spring-cloud-gateway` convenient as a BFF is that the swap from cookie to token is a filter:

```yaml
spring:
  cloud:
    gateway:
      server:
        webmvc:
          routes:
            - id: resource-server
              uri: ${resource-server-uri}
              predicates:
                - Path=/bff/api/**
              filters:
                - TokenRelay=
                - StripPrefix=2
```

`TokenRelay=` takes the access token from the authorized client in session and puts it in the `Authorization` header. Behind it, the resource server is an ordinary stateless API which knows nothing about sessions, cookies or the BFF. That separation is the point: the statefulness stops at the gateway.

It also means the access token is refreshed by the gateway, on the gateway's schedule, which is where the [refresh token stampede]({{ site.baseurl }}/articles/refresh-token-stampede/) comes from. A page loading five widgets at once, with an expired access token in session, is the exact shape of that problem.

## What the frontend looks like

Deliberately unglamorous, because the point is that nothing exotic is needed:

- `GET /me` to know who is logged in, answered anonymously so a logged-out frontend gets a body rather than an error.
- On `401` from any API call, either show a login button or navigate to `/oauth2/authorization/<registration>`.
- Read `XSRF-TOKEN`, send `X-XSRF-TOKEN` on anything which is not a `GET`.
- On the `2xx` responses from `/oauth2/authorization/**` and `/logout`, read `Location` and assign `window.location.href`.

The sample ships a single `index.html` doing exactly that with plain `fetch`, no framework, so the behaviour is visible rather than buried in an HTTP interceptor.

## Testing it without a browser and without Keycloak

The part which usually gets skipped. An OAuth2 client fetches the OpenID configuration at startup, so a full-context test needs the authorization server to answer, which is what WireMock is for. The login itself never has to happen: `@WithOidcLogin` puts an `OAuth2AuthenticationToken` with an `OidcUser` principal in the security context, and `oauth2Client(...).accessToken(...)` puts an authorized client where the `TokenRelay` filter will find it.

What is then worth asserting is precisely the list above: the `401` on a protected route, the `200` with a `Location` carrying `code_challenge_method=S256`, the `202` with a `Location` to the `end_session_endpoint`, the CSRF cookie without `HttpOnly`, and the Bearer token arriving at the resource server. Each of those is a property in the configuration, and each of them silently reverts to a browser-shaped default if the property is lost in a merge.

## What it adds up to

Written by hand, the list is a `SecurityFilterChain` plus an `AuthenticationEntryPoint`, an `AuthenticationSuccessHandler`, an `AuthenticationFailureHandler`, a `LogoutSuccessHandler`, a logout URI builder with provider-specific branches, an `OAuth2AuthorizationRequestResolver`, a CSRF repository and request handler, a Back-Channel Logout endpoint with its session registry, a `GrantedAuthoritiesMapper`, and an authorized client repository which is not the request-scoped default. None of it is difficult in isolation. All of it is security code which has to be right, and which every BFF rewrites identically.

That is the case for the properties. The counter-case, which deserves to be stated as plainly, is on the [risks and mitigations]({{ site.baseurl }}/oidc/risks/) page: this is a third-party dependency in the security layer, and the reason it is a reasonable one is that every bean above is `@ConditionalOnMissingBean`, so any single default can be taken back without giving up the rest. [What you would write without spring-addons]({{ site.baseurl }}/without-spring-addons/) names them one by one.
