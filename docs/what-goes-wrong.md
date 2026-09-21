---
title: What goes wrong without it
nav_order: 2
description: "Symptom by symptom, what Spring Security's OAuth2 defaults do to a Spring backend consumed by a single-page or mobile application: login redirections a fetch cannot follow, a CSRF token JavaScript cannot read, Keycloak roles that never become authorities, an open redirect after login, random logouts under load, tests that pass with authorities production never grants."
---

# What goes wrong without it
{: .no_toc }

[What you would write without spring-addons]({{ site.baseurl }}/without-spring-addons/) answers "what does the starter hide?". This page answers the question which comes before it: what happens to an application which does not take the dependency and does not know that these decisions exist.

The premise is that Spring Security's OAuth2 support was designed for a browser doing navigations: a form or an `oauth2Login` redirection, a session, a CSRF token rendered in a page. A Spring backend for a single-page or a mobile application is consumed by JavaScript doing `fetch`, or by an HTTP client in an app, and several of those defaults are silently wrong for it. None of them fails at startup. Each one shows up as a symptom in the frontend, a test that lies, or a hole nobody notices.

Two things to keep in mind while reading. First, none of this is impossible to write: a team fluent in Spring Security can do all of it, and the page linked above names the bean for each line. The argument is that these decisions have to be taken anyway, that they are easy to miss, and that each of them reverts to the browser-shaped default when a property is lost in a merge. Second, the starter keeps Spring's defaults unless told otherwise: the `2xx` statuses, the `401` entry point and the CSRF cookie are each one property, and the [`bff` sample](https://github.com/ch4mpy/spring-addons/tree/master/samples/bff) sets all of them.

1. TOC
{:toc}

## Where the tokens live decides everything else

Most tutorials for a single-page application put an OAuth2 public client in the browser: the JavaScript holds the access token and sends it as a `Bearer` header. The backend is then a plain resource server, and the first table below is all that applies to it.

The alternative, which the OAuth2 working group recommends for browser-based applications, is to keep the tokens on the server. The backend is then an OAuth2 client with `oauth2Login` and a session cookie, a Backend For Frontend, and relays the access token to the APIs. It removes the tokens from the reach of every script the page runs, it allows a confidential client with `refresh_token`, and it makes logout a server-side decision. It also puts the application squarely in the second table, which is where Spring Security's defaults are furthest from what a JavaScript caller needs. The reasoning is spelled out in [An OAuth2 BFF, end to end]({{ site.baseurl }}/articles/bff/).

## Resource servers: an API consumed with access tokens

Spring Boot's own resource server chain is a reasonable default for an API. It answers `401` to unauthenticated requests, and it does not require a CSRF token on requests carrying a `Bearer` token. What remains is below.

| What is observed | What Spring does by default | What it is | With `spring-addons-starter-oidc` |
|---|---|---|---|
| `hasRole('ADMIN')` never matches, even for an admin. | Authorities are read from the `scope` claim, prefixed with `SCOPE_`. Keycloak puts roles in `realm_access.roles` and `resource_access.*.roles`, Auth0 and Cognito elsewhere; none of those is read. | Broken behaviour, often "fixed" with `permitAll()` or with a converter which is rewritten and re-debugged for each provider. | `ops[].authorities[].path` is a JSON path in the claims, with a prefix and a case transform. |
| Preflight `OPTIONS` requests are answered `401`, the frontend sees a CORS error on every call. | CORS configured on the MVC side (`@CrossOrigin`, `WebMvcConfigurer`) runs after the security filters. A preflight carries no credentials, so it is rejected before reaching MVC. CORS has to be configured on the security chain. | Broken behaviour, often "fixed" by permitting all `OPTIONS` requests everywhere. | `cors[]` on the chain, with anonymous preflight requests. |
| Tokens from a second realm, tenant or provider must be accepted. | One issuer per `spring.security.oauth2.resourceserver.jwt.*` configuration. Several issuers is a `JwtIssuerAuthenticationManagerResolver` with one decoder, one validator set and one converter each. The tempting shortcut, building a decoder from the `iss` claim of the incoming token, trusts any issuer on the internet. | Security flaw when the shortcut is taken; otherwise code which is easy to get subtly wrong. | One entry per issuer in `ops[]`. Tokens from an issuer which is not listed are answered `401`. |
| Tests pass with authorities production never grants, or fail on authorities production does grant. | The `jwt()` request post-processor of `spring-security-test` builds the `Authentication` itself. The authentication converter of the application never runs. Testing a `@Service` needs a request, so it is done through a controller or not at all. | Tests that lie. | `@WithJwt("user.json")` runs the claim-set through the application's own converter, on any `@Component`. |

## Clients with `oauth2Login`: a BFF consumed by JavaScript

This is where the distance between the defaults and what is needed is widest.

| What is observed | What Spring does by default | What it is | With `spring-addons-starter-oidc` |
|---|---|---|---|
| A `fetch` to `/oauth2/authorization/{registration}` fails with an opaque CORS error. | `302` to the authorization server. The browser follows a redirection inside a `fetch`, cross-origin, and the authorization server's response has no CORS headers for that origin. | Broken behaviour. Login cannot start from JavaScript. | `oauth2-redirections.pre-authorization-code: 2xx status`: the `Location` header is set and the JavaScript navigates itself. The same for the callback and for logout. |
| An API call without a session gets a login page, or a redirection the frontend cannot use. | `LoginUrlAuthenticationEntryPoint` redirects to the login page or straight to the provider. | Broken behaviour. The frontend cannot tell "not logged in" from "the server is down". | `oauth2-redirections.authentication-entry-point: UNAUTHORIZED`. |
| Every `POST`, `PUT` and `DELETE` from the frontend is refused `403`. | The CSRF token lives in the session and is meant to be rendered in a page. JavaScript needs it in a cookie it can read and a header it can send. Spring Security 7 added `csrf.spa()` for the repository and the request handler, on the servlet side. | Broken behaviour, often "fixed" with `csrf.disable()`, which is a security flaw on a session-based application. | `csrf: cookie-accessible-from-js`: `XSRF-TOKEN` cookie without `HttpOnly`, `X-XSRF-TOKEN` header, BREACH-safe request handler, servlet and reactive. |
| The frontend wants the user back where they were after login or logout. | The saved request or a fixed default success URL. Letting the frontend pass a destination is application code, and if that destination is not validated the application is an open redirect ([CWE-601](https://cwe.mitre.org/data/definitions/601.html)). | Security flaw, in the code most applications end up writing. | `X-POST-LOGIN-SUCCESS-URI` and `X-POST-LOGOUT-SUCCESS-URI` headers, validated against `post-login-allowed-uri-patterns` and `post-logout-allowed-uri-patterns`. Scheme-relative URIs are always refused. |
| Logout does not end the session at Auth0 or Amazon Cognito. | RP-Initiated Logout as specified. Those two providers do not implement the specification, each in its own way. | Broken behaviour: the user is logged out of the application and still logged in at the provider. | `logoutRequestUriBuilder` knows the deviations. `logout-uri` and the parameter names are properties for any other provider. |
| The user signs out from another application of the same SSO realm and stays logged in here. | Back-Channel Logout has been supported since Spring Security 6.2, but is off. Turning it on needs the endpoint, the session registry, and the endpoint reachable without a session. | Missing behaviour, expected by anyone who sets up SSO. | `back-channel-logout.enabled: true` plus the endpoint in `permit-all`. |
| Users are logged out at random when a page fires several calls at once. | One `refresh_token` flow per concurrent request. With rotating refresh tokens, the first one wins and the others present a token which is no longer valid. [Declined upstream](https://github.com/spring-projects/spring-security/issues/15145). | Unexpected behaviour, invisible in development and reproducible only under load. | The authorized client provider is decorated so that concurrent requests on a session share one token request. Details in [one refresh token flow at a time]({{ site.baseurl }}/articles/refresh-token-stampede/). |
| Nothing: an authorization code injection leaves no symptom. | PKCE is enabled for public clients only, which is what RFC 7636 was written for. The OAuth 2.1 draft requires it for every client. | Hardening most deployments want and few ask for. | `pkce-forced: true`. |

## Outgoing calls: REST clients

`spring-addons-starter-rest` does not depend on the OIDC starter, and the failures below are of a different kind: not security holes, but behaviours discovered in the environment where the application is deployed rather than on a workstation.

| What is observed | What happens by default | With `spring-addons-starter-rest` |
|---|---|---|
| Calls from a scheduled job or a message listener fail, or a token is fetched per call. | The `DefaultOAuth2AuthorizedClientManager` of a web application is bound to the current request. Outside one, the tempting fix is a manual `client_credentials` request on each call. | `authorization.oauth2.oauth2-registration-id`. With only `client_credentials` registrations, the OIDC starter picks an `AuthorizedClientServiceOAuth2AuthorizedClientManager`, which needs no request and reuses the token until it expires. |
| The incoming user's token must be forwarded, and the code to do it is copied between services. | Nothing: reading the `Authentication`, unwrapping the right token type and skipping anonymous requests is application code. | `authorization.oauth2.forward-bearer: true`. |
| Works on a workstation, times out in the cluster. | Java's HTTP clients do not read `HTTP_PROXY` and `NO_PROXY`. The `NO_PROXY` wildcard and leading-dot rules, and proxy credentials on an HTTPS tunnel, are code. | Proxy settings from the environment by default, overridable per client. |
| Works against the public endpoint, fails against the internal one with a self-signed certificate. | A `ClientHttpRequestFactory` per client, an SSL bundle, and the choice of the underlying HTTP library, in code. | `ssl-bundle`, `ssl-certificates-validation-enabled`, `client-http-request-factory-impl`, as properties. |

## What this page does not claim

It does not claim that these starters are the only way to get any of it: every line has a hand-written equivalent, listed on [what you would write without spring-addons]({{ site.baseurl }}/without-spring-addons/), and most of them are a few dozen lines.

It does not claim that a server-rendered application needs any of this. A Thymeleaf application with `oauth2Login` and no JavaScript caller is well served by Spring Security's defaults, and this starter would only add a dependency.

It does not claim that the dependency is free. It is third-party code in the security layer, and the case against it is on the [risks and mitigations]({{ site.baseurl }}/oidc/risks/) page, with what mitigates it: every auto-configured bean is `@ConditionalOnMissingBean`, so each decision above can be taken back one at a time without giving up the rest.

What it does claim is that the decision should not be reduced to "a simple API with one issuer does not need it". That application still has the authorities mapping, the security-side CORS and the tests to get right, and the moment its frontend moves the tokens out of the browser, it has everything in the second table.
