---
title: Clients with oauth2Login
parent: spring-addons-starter-oidc
nav_order: 2
description: "Configuring a Spring Boot OAuth2 client from properties: authorization code with PKCE, RP-Initiated Logout, Back-Channel Logout, CSRF for single-page applications, post login and logout URIs, and concurrent refresh token flows."
---

# OAuth2 clients with `oauth2Login`

OAuth2 clients are applications fetching tokens from an authorization server to later authorize queries to a resource server. Spring Security `oauth2Login` configures the authorization code and the refresh token flows.

When `oauth2Login` is configured on a filter chain, this filter chain has to be stateful (tokens are stored in sessions) and protected against CSRF.

Note that `spring-addons-starter-oidc` creates default `(Reactive)OAuth2AuthorizedClientProvider` and `(Reactive)OAuth2AuthorizedClientManager` for all OAuth2 clients (even when the `clientSecurityFilterChain` with `oauth2Login` is disabled) to handle additional parameters on token request. As usual, you can opt out of these default beans by exposing your own.

The `(Reactive)OAuth2AuthorizedClientManager` implementation is chosen from the flows declared with `spring.security.oauth2.client.registration.*` properties:
- only `authorization_code` registrations: a `Default(Reactive)OAuth2AuthorizedClientManager`, which stores the authorized clients in the `(Server)OAuth2AuthorizedClientRepository` and requires an `HttpServletRequest` (or a `ServerWebExchange`)
- no `authorization_code` registration, which is the case of a resource server consuming another resource server with `client_credentials`: an `AuthorizedClientService(Reactive)OAuth2AuthorizedClientManager`, which stores the authorized clients in the `(Reactive)OAuth2AuthorizedClientService` and needs no request at all. Tokens are then reused across requests instead of being requested again for each of them, which is what Spring Boot defaults lead to in a stateless application.
- both: a `PerRegistration(Reactive)OAuth2AuthorizedClientManager` delegating to one of the two above, depending on the flow of the registration to authorize

When at least one registration uses `authorization_code`, a `HttpSessionOAuth2AuthorizedClientRepository` (or `WebSessionServerOAuth2AuthorizedClientRepository` in a reactive application) is also exposed, in place of the Spring Boot default which keeps the authorized clients in a map local to the JVM. This matters for a BFF: tokens follow the session, which means that they are replicated by Spring Session and released when the session is closed.

## Client `Security(Web)FilterChain`
A client filter chain with `oauth2Login` is created if (and only if) all the following conditions are met:
- `spring-boot-starter-oauth2-client` is on the classpath
- `spring.security.oauth2.client.registration` contains at least one entry with `authorization-grant-type=authorization_code`
- `com.c4-soft.springaddons.oidc.client.security-matchers` is not empty

This filter chain is configured with the following defaults:
- `@Order(Ordered.LOWEST_PRECEDENCE - 1)` (just before the resource server one, which is the default chain)
- the security-matcher in the conf is applied
- stateful (session and CSRF protection enabled)
- oauth2Login
- enabled RP-Initiated Logout (provided that the OpenID configuration exposes an end-session endpoint or that spring-addons properties for non-standard logout are there)
- disabled Back-Channel Logout
- disabled PKCE
- disabled CORS (as a reminder, `cors` properties configure a global filter)
- allowed anonymous access to pre-flight requests and to all requests with a path matching an entry in `permit-all`; all other requests requiring a valid authentication

## Setting a Base URI for the Client
Authorization-code flow and RP-Initiated Logout involve some redirection to the authorization server and then back to the client.

Spring Security generates this redirection URIs, but sometimes, it is convenient to have it point to another host than the client itself: a gateway, reverse-proxy, ingress or whatever. `com.c4-soft.springaddons.oidc.client.client-uri` serves that purpose.

## Authorization Code
It is possible to force PKCE usage even for confidential clients by setting `com.c4-soft.springaddons.oidc.client.pkce-forced=true` (By default, Spring enables PKCE only for "public" clients).

Other features are of interest mainly in the case of remote frontends connected to a Spring backend with `oauth2Login` (OAuth2 BFF).

Customization can be achieved by exposing a variety of beans:
- `PreAuthorizationCode(Server)RedirectStrategy`: the default is `SpringAddonsPreAuthorizationCode(Server)RedirectStrategy` which allows changing the status of the redirection to the authorization server when initiating an authorization code flow (`com.c4-soft.springaddons.oidc.client.oauth2-redirections.pre-authorization-code` property, `X-RESPONSE-STATUS` header or. `response_http_status` request parameter). This can be of use for frontends wishing to switch the HTTP client on the fly (like a mobile app using a programmatic client with a session on the Spring client and a web-view or system browser with another session for login on the authorization server)
- `(Server)OAuth2AuthorizationRequestResolver`: the default is `SpringAddons(Server)OAuth2AuthorizationRequestResolver` which:
  * forces PKCE usage if the `pkce-forced` is set to `true`
  * switches the client base URI (if requested)
  * saves in session the post-login success and failure URI (provided as `X-POST-LOGIN-SUCCESS-URI` & `X-POST-LOGIN-FAILURE-URI` headers or `post_login_success_uri` & `post_login_failure_uri` request params)
  * adds optional request params defined under `com.c4-soft.springaddons.oidc.client.authorization-params.{registrationId}`. Auth0 for instance, requires an `audience` parameter to be added to authorization request (see FAQ for a sample).
- `(Server)AuthenticationSuccessHandler`: the default restores the post-login success URI saved in the session and applies the `com.c4-soft.springaddons.oidc.client.oauth2-redirections.post-authorization-code`
- `(Server)AuthenticationFailureHandler`: the default restores the post-login failure URI saved in the session and applies the `com.c4-soft.springaddons.oidc.client.oauth2-redirections.post-authorization-code`

To clarify, you can define default post-login URL in application properties and override it from the frontend at login time by setting a header or providing a request parameter. A frequent use case is to re-activate the current route in the frontend after the authorization-code flow is completed.

Last, the Spring default status for unauthorized requests (`302` redirect to login) is kept, but it can be changed to anything else using `com.c4-soft.springaddons.oidc.client.oauth2-redirections.authentication-entry-point`. For instance, it could be wise to set it to `UNAUTHORIZED` on an OAuth2 BFF for single page or mobile applications, or in stateful REST API.

## RP-Initiated Logout
Most OpenID Providers implement the RP-Initiated Logout and expose an `end_session_endpoint` in OpenID configuration, but some, like Auth0 and Cognito don't: they have a logout mechanism which works mostly like RP-Initiated Logout but with an endpoint URI and request params to find in docs. 

Sample for registrations called `cognito-user` and `auth0-user`:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          oauth2-logout:
            cognito-user:
              uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: logout_uri
            auth0-user:
              uri: ${auth0-issuer}v2/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: returnTo
```

## Back-Channel Logout
Back-Channel Logout is an OpenID standard that allows a client to be notified by the authorization server of logout events initiated by another client. It is some *"single sign-out"* for systems with *Single Sign On* (SSO). Keycloak is a sample of an OpenID Provider capable of emitting Back-Channel Logout to a Spring client (like a Gateway used as an OAuth2 BFF). It is disabled by default. The default internal logout URI and session cookie name can be overriden in properties:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          back-channel-logout:
            enabled: true
            # Those two are optional, defaults should work in most scenarios
            internal-logout-uri: ${gateway-uri}/logout/connect/back-channel/quiz-bff
            cookie-name: JSESSION-ID
```

## Authorities Converter
By default, a `GrantedAuthoritiesMapper` using the authorities converter bean in the application context. The default for this authorities converter is shared with resource servers: `ConfigurableClaimSetAuthoritiesConverter`. The configuration for this converter is resolved by the `OpenidProviderPropertiesResolver` in the context.

## CSRF protection
Requests to an OAuth2 client are authorized with session cookies, which exposes it to CSRF attacks. Consequently, **CSRF protection should always be enabled on OAuth2 clients**.

The default with `spring-addons-starter-oidc` is the same as with `spring-boot-starter-oauth2-client` (session).

When setting `com.c4-soft.springaddons.oidc.client.csrf=cookie-accessible-from-js`, as needed by single-page and mobile applications, the CSRF token is exposed in a token and the required filter is registered.

Application configuration can get complete control over the CSRF cookie and repo by exposing a `Cookie[Server]CsrfTokenRepositoryPostProcessor`. Sample for a servlet app:
```java
@Bean
CookieCsrfTokenRepositoryPostProcessor csrfCookiePostProcessor() {
  return csrfCookieRepo -> {
    csrfCookieRepo.setCookieCustomizer(csrfCookie -> csrfCookie.sameSite("Strict"));
    return csrfCookieRepo;
  };
}
```

In reactive applications, the CSRF token is deferred and the cookie is written only when something subscribes to it: this is done by a `WebFilter` bean named `csrfCookieWebFilter`. As `WebFilter` is too broad a type to back off on, this default is conditional on the bean **name**: to replace it, name yours `csrfCookieWebFilter`, otherwise both filters run. The resource server filter chain registers the same bean under the same name.

## Access Control
The default access rule is set to `isAuthenticated()` with two exceptions:
- routes matching the path-matchers listed in `permit-all` property for which anonymous requests are allowed
- pre-flight requests, unless disabled in `cors` properties (`OPTIONS` requests to routes matching the path-matchers listed in CORS properties).

The most convenient way to define fine-grained access control is probably to `@Enable(Reactive)MethodSecurity` and to decorate `@RestController` methods with `@PreAuthorize`.

For those preferring access control in configuration (or when you don't write the endpoint yourself), you can expose a `@Bean` of type `ClientExpressionInterceptUrlRegistryPostProcessor` or `ClientAuthorizeExchangeSpecPostProcessor`.

## Post-Process the Client Filer-Chain
By exposing a `Client(Server)HttpSecurityPostProcessor` bean, you get complete control of the `(Server)HttpSecurity` configured in the `clientSecurityFilterChain` just before it is built. This allows changing anything that was pre-configured.

## Add Parameters to Token Requests
Some OpenID Providers require some extra parameters on the token endpoint. Auth0 for instance expects an `audience` parameter with client-credential token requests. Such parameters can be defined under `com.c4-soft.springaddons.oidc.client.token-params.{registrationId}` (see FAQ for a sample).

## Post login/logout URIs
Post login URIs can be provided by the frontend with `X-POST-LOGIN-SUCCESS-URI` & `X-POST-LOGIN-FAILURE-URI` headers or `post_login_success_uri` & `post_login_failure_uri` with the request initiating authorization-code flow. Some defaults can be provided with `post-login-redirect-host` and `post-login-redirect-path` application properties.

Similarly, Post logout URI can be provided by the frontend with `X-POST-LOGOUT-SUCCESS-URI` header or `post_logout_success_uri` with the request initiating RP-Initiated Logout. This URI will be added as a request parameter to the Location header redirecting to the authorization server after the session is closed on the OAuth2 client. Some defaults can be provided with `post-logout-redirect-host` and `post-logout-redirect-path` application properties.

Since `8.1.13`, to prevent [Open Redirect (CWE-601)](https://cwe.mitre.org/data/definitions/601.html) attacks, the post login/logout URIs must be part of whitelists defined with `post-login-allowed-uri-patterns` and `post-logout-allowed-uri-patterns` properties. For backward compatibility, if these properties are left blank, all post login/logout URIs composed of only a path (no scheme / authority) as well as those with the same scheme and authority as the `client-uri` property are allowed. Whatever the patterns, scheme-relative URIs (starting with `//`, which user-agents resolve to another host) are always refused.

Sample configuration stricter than defaults:
```yaml
reverse-proxy: https://localhost

com:
  c4-soft:
    springaddons:
      oidc:
        client:
          client-uri: ${reverse-proxy}/bff
          post-login-allowed-uri-patterns:
          # Each entry is compiled into a java.util.regex.Pattern
          # The following is stricter than the defaults, which are ^${reverse-proxy}(/.*)?$ and ^/.*$
          - ^${reverse-proxy}/ui(/.*)?$
          - ^/ui(/.*)?$
          post-login-redirect-path: /ui/greet
          post-logout-allowed-uri-patterns:
          - ^${reverse-proxy}/ui(/.*)?$
          - ^/ui(/.*)?$
          post-logout-redirect-path: /ui/
```
Each `post-login-allowed-uri-patterns`/`post-logout-allowed-uri-patterns` entry is compiled into a `java.util.regex.Pattern`.

`post-login-redirect-host`, `post-login-redirect-path`, `post-logout-redirect-host`, and `post-logout-redirect-path` are validated at startup. An exception is thrown in case of mismatch.

In case of mismatch of post login/logout headers & request params, the authentication request is answered with a `401`.

## Concurrent Refresh Token Flows
Most authorization servers rotate refresh tokens: the one which was used is revoked as soon as a new one is issued. When a user-agent sends parallel requests while the access token in session is expired, Spring Security fires one `refresh_token` flow per request, only one of them can succeed, and all the other requests are answered with a `401`. Two requests sent in less time than a token request takes are enough for this to happen, so this is not limited to high throughput applications: a single page application refreshing a few widgets at once is a typical victim. This is a known limitation of Spring Security, see [spring-security#15145](https://github.com/spring-projects/spring-security/issues/15145).

To work around it, `spring-addons-starter-oidc` decorates the `RefreshToken(Reactive)OAuth2AuthorizedClientProvider` it builds with a `SingleRefreshTokenFlow(Reactive)OAuth2AuthorizedClientProvider`: the first request to reach the provider runs the flow and the others wait for its result. The authorization server sees a single token request and the refresh token is spent exactly once.

Flows are keyed with a digest of everything which defines the token request to run: the client registration ID, the principal name, the access and refresh token values, and the requested scopes, if any. Two requests share a flow if and only if they would send the exact same payload to the token endpoint, which, with a session scoped `(Server)OAuth2AuthorizedClientRepository`, means "requests from the same session". Requests from other sessions hold other refresh tokens and keep being refreshed in parallel.

The result of a flow is also shared for a short while after it completed. This covers the requests which had loaded the authorized client from the session just before the refreshed one was saved there: without it, they would replay a refresh token which is already spent. Failures are shared too, because replaying a refresh token which the authorization server already rotated can have it revoke the whole token family.

Defaults should fit most applications, but everything is configurable:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          single-refresh-token-flow:
            # set to false to restore the Spring Security behavior (one flow per request)
            enabled: true
            # how long a request waits for the flow it joined before giving up with a server_error
            timeout: PT30S
            # how long the result of a successful flow is shared. Keep it well below the access token lifespan.
            success-caching-duration: PT10S
            # how long the failure of a flow is shared. Set to PT0S to have each request run its own flow after a failure.
            error-caching-duration: PT10S
```

This applies to the `(Reactive)OAuth2AuthorizedClientProvider` auto-configured by this starter. If you expose your own, decorate its `refresh_token` provider yourself:
```java
@Bean
OAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider(SpringAddonsOidcProperties addonsProperties) {
  var refreshTokenProvider = new RefreshTokenOAuth2AuthorizedClientProvider();
  // further configuration of the refresh_token provider
  return new DelegatingOAuth2AuthorizedClientProvider(
      new AuthorizationCodeOAuth2AuthorizedClientProvider(),
      new SingleRefreshTokenFlowOAuth2AuthorizedClientProvider(
          refreshTokenProvider, addonsProperties.getClient().getSingleRefreshTokenFlow()));
}
```

### Horizontally Scaled Applications
Flows are de-duplicated inside a single JVM. Behind a load balancer without session affinity, parallel requests from one user-agent land on several instances and each runs its own flow, so the problem returns divided by the number of instances. **Session affinity at the ingress removes it entirely and costs nothing**, with Spring Session still earning its keep for failover and rolling restarts. That is the answer to prefer, and it is why spring-addons stops here.

Note that Spring Session cannot be pressed into service as a distributed lock: `SessionRepository` exposes only `createSession`, `save`, `findById` and `deleteById`, with no lock, no compare-and-swap and no version, so a "lock" written as a session attribute is a read-modify-write two instances win at once. Its default `FlushMode` is `ON_SAVE`, so the refreshed authorized client only reaches the store when the holder's whole request ends, and `SessionRepositoryFilter` hands each request a snapshot it keeps reading.

If you really need cross-instance de-duplication, write your own decorator in place of `SingleRefreshTokenFlow(Reactive)OAuth2AuthorizedClientProvider` in the `@Bean` above, and back it with whatever your cluster already runs. Hints from the implementation here:
- key on the token request, not on the session: a digest of the registration ID, the principal name, the access and refresh token values, and the requested scopes. Two requests must share a flow if and only if they would send the same payload to the token endpoint. The session ID is neither available in the `OAuth2AuthorizationContext` nor needed.
- share the **outcome**, not just a lock. A lock alone leaves the other instances with nothing to read: they cannot get the result from the session for the `FlushMode` and snapshot reasons above.
- keep sharing that outcome for a few seconds after the flow completed. Requests which loaded the authorized client from the session just before the refreshed one was saved there would otherwise replay a refresh token which is already spent.
- share failures too, briefly. Replaying a refresh token the authorization server already rotated can have it revoke the whole token family.
- put an expiry on everything: a lease on the lock, so an instance going down does not block the others, and a retention on the outcome, so nothing outlives the tokens it holds.
- store only the principal name and the tokens, never the `ClientRegistration`, whose serialization carries the client secret. Rebuild the `OAuth2AuthorizedClient` around the registration you already have in the context.
- treat a store failure as a miss: log it and run the flow locally. Degrading to one flow per instance is no worse than not having a store at all, and much better than failing authorization.
- raise `server_error` and not `invalid_grant` when a request gives up waiting. `invalid_grant` makes `RemoveAuthorizedClientOAuth2AuthorizationFailureHandler` evict the authorized client from the session, and nothing proved the refresh token invalid.

