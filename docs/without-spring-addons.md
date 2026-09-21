---
title: What you would write without it
nav_order: 6
description: "Bean by bean, the Spring Security code spring-addons-starter-oidc and spring-addons-starter-rest replace: JwtAuthenticationConverter, JwtIssuerAuthenticationManagerResolver, AuthenticationEntryPoint, logout handlers, OAuth2AuthorizedClientManager and the rest."
---

# What you would write without spring-addons
{: .no_toc }

The honest objection to a third-party starter in the security layer is that it hides what it does. This page is the answer: for every concern these starters auto-configure, it names the bean and the hand-written Spring Security code it stands for.

It is worth reading even if the conclusion is not to take the dependency. Everything below is ordinary Spring Security, and knowing which bean owns which decision is what makes the framework configurable in the first place.

Two properties make this a menu rather than a package deal. Every bean listed here is `@ConditionalOnMissingBean`, so defining one of them in the application takes that single decision back and leaves the rest auto-configured. And the auto-configured filter chains have the lowest precedence, so an application can always add a chain of its own with a stricter security matcher in front of them.

1. TOC
{:toc}

## Resource servers

Auto-configured by `SpringAddonsOidcResourceServerBeans` and `SpringAddonsOidcBeans`.

| Concern | The auto-configured bean | What it replaces |
|---|---|---|
| The chain itself | `springAddonsJwtResourceServerSecurityFilterChain` | A `SecurityFilterChain` wiring `sessionManagement` to stateless, `csrf` disabled, `cors`, `authorizeHttpRequests`, `exceptionHandling` and `oauth2ResourceServer`, and keeping the four consistent with each other. |
| Authorities mapping | `authoritiesConverter` (a `ClaimSetAuthoritiesConverter`) | A `JwtGrantedAuthoritiesConverter` subclass, or a `Converter<Jwt, Collection<GrantedAuthority>>`, reading the claim the provider actually uses. Keycloak nests roles under `realm_access.roles` and `resource_access.*.roles`, Auth0 and Cognito use other claims, so this code is rewritten for every provider. |
| Building the `Authentication` | `jwtAuthenticationConverter` (a `JwtAbstractAuthenticationTokenConverter`, backing off for any `Converter<Jwt, ? extends AbstractAuthenticationToken>` bean whatever its name) | A `JwtAuthenticationConverter` holding the converter above and setting the principal name from the right claim. Exposing it as a bean rather than a lambda inside the chain is also what makes `@WithJwt` able to run it in tests. |
| Several issuers | `authenticationManagerResolver` and `springAddonsJwtDecoderFactory` | A `JwtIssuerAuthenticationManagerResolver` with one `JwtDecoder`, one validator set and one authentication converter per issuer, plus the code which decides which is which. |
| Token introspection | `springAddonsIntrospectingResourceServerSecurityFilterChain` | A second chain for opaque tokens, with an `OpaqueTokenIntrospector` and an `OpaqueTokenAuthenticationConverter`. In the samples this is a Spring profile, not a code change. |
| CORS | `corsFilter` | A `CorsConfigurationSource` bean plus the `cors` configuration on the chain, and the decision about preflight requests reaching the chain anonymously. |
| Access control | `authorizePostProcessor` | The `authorizeHttpRequests` block. With spring-addons only the anonymous routes are listed in properties, the rest stays on `@PreAuthorize` next to the code it protects. |
| Escape hatch | `httpPostProcessor` | Nothing: this one exists so that an application can reach the `HttpSecurity` builder without redefining the whole chain. |

The [`resource-server`](https://github.com/ch4mpy/spring-addons/tree/master/samples/resource-server) sample states the same thing in one paragraph: accepting Keycloak tokens with roles from `realm_access.roles`, `preferred_username` as name, one public route, CORS for a single-page application and `401` instead of a login redirect is a `SecurityFilterChain` with `sessionManagement`, `csrf`, `cors` and a `CorsConfigurationSource`, `authorizeHttpRequests`, `exceptionHandling`, and `oauth2ResourceServer` configured with a `JwtAuthenticationConverter` holding a custom `JwtGrantedAuthoritiesConverter`. Add a second issuer and a `JwtIssuerAuthenticationManagerResolver` joins the list.

## Clients with `oauth2Login`, and BFFs

Auto-configured by `SpringAddonsOidcClientWithLoginBeans` and `SpringAddonsOAuth2AuthorizedClientBeans`. This is where the gap is widest, because a browser client consumed by a JavaScript frontend needs several behaviours Spring Security does not default to.

| Concern | The auto-configured bean | What it replaces |
|---|---|---|
| The chain itself | `springAddonsClientFilterChain` | A `SecurityFilterChain` with `oauth2Login`, sessions, CSRF and a logout configuration. |
| Authorization code with PKCE | `oAuth2AuthorizationRequestResolver` | An `OAuth2AuthorizationRequestResolver` forcing PKCE, remembering where the frontend wants to land after login, and adding the extra parameters a provider requires (the Auth0 `audience`, the Keycloak `kc_idp_hint`). |
| Logout | `logoutRequestUriBuilder` and `logoutSuccessHandler` | A `LogoutSuccessHandler` building the RP-Initiated Logout URI, and, for Auth0 and Amazon Cognito, the code which papers over the fact that they do not implement the specification. |
| Back-Channel Logout | `oidcBackChannelLogoutHandler` and `oidcSessionRegistry` | The logout token endpoint, the session registry mapping provider sessions to server sessions, and the invalidation. |
| Statuses a SPA can consume | `authenticationSuccessHandler`, `authenticationFailureHandler`, `authorizationCodeRedirectStrategy` | Handlers returning `2xx` with a `Location` header instead of `3xx`, so that the frontend navigates itself rather than letting the browser follow a cross-origin redirection inside a `fetch`. |
| Unauthorized requests | `authenticationEntryPoint` | An `AuthenticationEntryPoint` answering `401` instead of redirecting to the login page, when the caller is JavaScript rather than a browser navigation. |
| Expired session | `invalidSessionStrategy` | The equivalent decision for a session which has gone. |
| CSRF for JavaScript | the CSRF cookie configuration | `CookieCsrfTokenRepository.withHttpOnlyFalse()` plus the `CsrfTokenRequestHandler` dance which makes the cookie actually written. |
| Authorities from the ID token | `grantedAuthoritiesMapper` | A `GrantedAuthoritiesMapper` doing for the login flow what the authorities converter does for access tokens. |
| Tokens in session | `authorizedClientRepository` | An `HttpSessionOAuth2AuthorizedClientRepository` so the tokens follow the session, rather than the request-scoped default. |
| Concurrent refresh | `authorizedClientManager` and `oauth2AuthorizedClientProvider` | Nothing you can reasonably write. See below. |

### The refresh token stampede

Most authorization servers rotate refresh tokens. When a user-agent fires parallel requests while the access token in session has expired, Spring Security runs one `refresh_token` flow per request. The first one succeeds and rotates the token, the others present a refresh token which is no longer valid and are answered with a `401`, which the user sees as a random logout under load.

This was [declined upstream](https://github.com/spring-projects/spring-security/issues/15145) as something the framework cannot solve generally, and the reasoning holds: a general solution would have to make assumptions about how sessions are stored. `spring-addons-starter-oidc` decorates the authorized client provider so that concurrent requests on the same session share a single token request, and the authorization server sees one flow rather than five.

## REST clients

Auto-configured by `spring-addons-starter-rest`, which does not depend on the OIDC starter.

| Concern | What it replaces |
|---|---|
| Forwarding the incoming Bearer | A `ClientHttpRequestInterceptor` reading the `Authentication` from the `SecurityContextHolder`, unwrapping the right token type, and skipping anonymous requests. |
| Calling as the application | An `OAuth2AuthorizedClientManager` wired to a `ClientRegistrationRepository` and an `OAuth2AuthorizedClientService`, **not** the request-scoped repository Spring Boot defaults to in a web application, or a token is fetched for every call. Then an `OAuth2ClientHttpRequestInterceptor` with a fixed registration ID and a principal resolver tolerating the absence of a user. |
| Proxies | Reading `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`, implementing the wildcard and leading-dot rules of `NO_PROXY` by hand, and carrying proxy credentials through an HTTPS tunnel. |
| SSL and timeouts | A `ClientHttpRequestFactory` per client, and the code to swap the underlying HTTP library when the default one sets headers some middleware rejects. |
| `@HttpExchange` proxies | Wiring each group of generated proxies to a client carrying the right base URL, headers, authorization and request factory. |

## Tests

| Concern | What it replaces |
|---|---|
| A security context on a controller | `spring-security-test` post-processors and mutators do this, but they build the `Authentication` themselves and never run the authentication converter of the application, so the authorities under test are not the authorities in production. |
| A security context anywhere else | Building the `Authentication` by hand and pushing it into the `SecurityContextHolder` in a `@BeforeEach`, for every `@Service` and `@Repository` test. |
| Claims that match the provider | Keeping the test fixtures honest with what the authorization server really emits. `@WithJwt("brice.json")` reads a claim-set from the test classpath, which can be copied from a real token. |

## Taking a decision back

Nothing here is all or nothing. To own the authorities mapping and keep everything else, define a `ClaimSetAuthoritiesConverter` bean. To own the whole resource server chain, define a `SecurityFilterChain`. At that point `spring-addons-starter-oidc` contributes nothing to the chain any more, and the dependency can be dropped whenever it suits, with the code already written.

That, rather than the number of lines saved, is the argument: the starters are a set of defaults for decisions which have to be taken anyway, and each one is reversible on its own.
