---
title: FAQ
parent: spring-addons-starter-oidc
nav_order: 4
description: "Auth0 audiences, Keycloak realms created at runtime, Microsoft Entra ID caveats, HTTP proxies in front of the token endpoint, cookies, Basic auth alongside OAuth2, and what exactly is auto-configured."
---

# Frequently asked questions


## What exactly is auto-configured?
To get an exhaustive insight of what is loaded, start with `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` which is the standard Spring Boot resource. It lists `@AutoConfiguration` files that Spring Boot will use when building the application context.

You may check the implementation of the condition on each `@AutoConfiguration` (and imported `@Configuration`) to limit your investigations to what is loaded in your application.

## Are all those beans defined by `spring-addons-starter-oidc` added to my application context?
**No!** All beans are conditional and only a few are instantiated. Which ones exactly depend on the application type (servlet or reactive), dependencies (resource server, client, or both), properties, and explicit beans definitions (most `spring-addons-starter-oidc` beans are `@ConditionalOnMissingBean`).

## Why all this fuss around authorities mapping? Can't I just keep the default using scopes?
The short answer is some OpenID Providers won't put roles in scope. 

The reason for that is it is not quite the same concept: In RBAC, a *role* is an attribute of the user, while an OAuth2 scope is an attribute of the client. Scope defines what a resource owner allows an OAuth2 client to do on his behalf on the resource server(s) included in the audience. You can think of the scope as a mask over user roles.

Scopes are of interest mainly when you want to give users control over which software can access which of their resources.

Roles are of interest when you want to control which user can access which resource, independently of the software he uses for that.

## How to configure a resource server to accept tokens issued for Keycloak *realms* created at runtime?
See the Multi-Tenancy section in resource server features.

## How to provide the `audience` parameter required by Auth0 for user login?
Add it to `com.c4-soft.springaddons.oidc.client.authorization-params.{registrationId}`. For instance, given an `auth0-user` registration in boot properties:
```yaml
issuer: https://dev-ch4mpy.eu.auth0.com/

spring:
  security:
    oauth2:
      client:
        provider:
          auth0:
            issuer-uri: ${issuer}
        registration:
          auth0-user:
            provider: auth0
            client-id: change-me
            client-secret: change-me
            authorization-grant-type: authorization_code
            scope: openid, offline_access
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          authorization-params:
            auth0-user:
              audience: demo.c4-soft.com
```
Note how the `auth0-user` registration ID is used in both Spring Boot `registration` and spring-addons `authorization-params`. Each entry is a map of parameter name to value (or list of values). The former `authorization-request-params` list syntax (`- name: audience` / `value: ...`) is deprecated: it still works, but the map syntax above does not bind to it.

## How to provide the `audience` parameter reuqired by Auth0 for client-credentials?
Add it to `com.c4-soft.springaddons.oidc.client.token-params.{registrationId}`. For instance, given an `auth0-api` registration in boot properties:
```yaml
issuer: https://dev-ch4mpy.eu.auth0.com/

spring:
  security:
    oauth2:
      client:
        provider:
          auth0:
            issuer-uri: ${issuer}
        registration:
          auth0-api:
            provider: auth0
            client-id: change-me
            client-secret: change-me
            authorization-grant-type: client_credentials
            scope: read:users
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          token-params:
            auth0-api:
              audience: demo.c4-soft.com
```
Note how the `auth0-api` registration ID is used in both Spring Boot `registration` and spring-addons `token-params` (same map syntax as `authorization-params`; `token-request-params` is the deprecated list syntax).

## Can a frontend override the response status for OAuth2 redirections?
Yes. `SpringAddonsOauth2(Server)RedirectStrategy`, which is the default for OAuth2 redirections, searches for an `X-RESPONSE-STATUS` header or `response_http_status` request param, and, if any, uses it to override the default picked in application properties.

## Is `iss` configuration property mandatory?
No. But be aware that with what follows, the `iss` (issuer) claim validation is disabled and that the JWT decoder will only check the token signature. As the issuer and audience should always be validated in a decently secured application, **the hacks below are not recommended**.

On a Spring `oauth2ResourceServer` with a JWT decoder, what is mandatory is to provide at least:
- one of `iss` or `jwk-set-uri` for the JWT decoder to be provided with a JWK-set (the JWK-set URI is exposed in the OpenID configuration usually available from `{iss}/.well-known/openid-configuration`, reason for the `jwk-set-uri` property to be optional when `iss` property is provided and its value accessible on the network)
- an `OpenidProviderPropertiesResolver` to retrieve the configuration (and the associated JWT decoder) from token claims. The default matching `iss` claim to `iss` property, if the later is not provided (or is not exactly the value in tokens like in a "dynamic" multi-tenant scenario), then you need to expose your own `OpenidProviderPropertiesResolver` bean.

Note that if the issuer is not provided in conf, the JWT decoder is not configured with an issuer validator. Unless audience is provided, the only validator is the signature one (using the JWK-set). Sample:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - jwk-set-uri: https://oidc.c4-soft.com/auth/realms/quiz/protocol/openid-connect/certs
```
```java
@Component
public class FirstOpenidProviderPropertiesResolver implements OpenidProviderPropertiesResolver {
    private final Optional<OpenidProviderProperties> opProperties;
    
    public FirstOpenidProviderPropertiesResolver(SpringAddonsOidcProperties properties) {
        this.opProperties = properties.getOps().isEmpty() ? Optional.empty() : Optional.of(properties.getOps().get(0));
    }

    @Override
    public Optional<OpenidProviderProperties> resolve(Map<String, Object> claimSet) {
        return opProperties;
    }
}
```
This seems dumb but will work in a single tenant scenario: the 1st (and only) OpenID Provider properties group is always matched and only tokens signed by the issuer we trust are considered valid.

On a Spring OAuth2 client with `oauth2Login`, OpenID auto-configuration relies on the *Issuer Identifier* to be set as `spring.security.oauth2.client.provider.{provider-id}.issuer-uri`. If for some reason the authorization server is not accessible using the *Issuer Identifier* (misconfigured containerized environments) or does not match the OpenID spec (Microsoft with V1 tokens), we should leave the `issuer-uri` empty, and manually provide URIs for `authorization`, `token`, `jwk-set`, and `userinfo` endpoints instead of relying on OpenID auto-configuration.

## Why can't I get things working easily with Microsoft authorization servers?
Microsoft authorization servers (like Entra ID, formerly known as Azure Active Directory, or AAD, or Azure AD B2C, etc.),  look like OIDC Providers but aren't with the V1 token format, which is the default.

[The OIDC discovery spec](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) states that *"OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by concatenating the string `/.well-known/openid-configuration` to the Issuer"*. Also, [the OpenID token validation spec](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) requires that *"The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim"*.

To have Microsoft Entra ID follow these OIDC discovery & OpenID token specifications requirements and issue JWT access token, we should:
- set `api.requestedAccessTokenVersion: 2` under `Applications` -> `App registrations` -> `{appName}` -> `Manifest` -> `Microsoft Graph App Manifest (New)` in Entra admin console
- ensure that hybrid flow is completely deactivated
- declare an audience (*"API"* in Entra admin console) and request it as scope with the authorization request (authorization request should contain `scope=openid {apiId}`) 

Intuitive...

## How to add other request authorization mechanisms like `Basic` auth?
Each request authorization mechanism should stand in a security filter chain of its own.

When a Spring application is configured with more than one security filter chain, these filter chains should be:
- Ordered: bean definitions should be decorated with `@Order` having different values.
- All but the last filter chain in `@Order` should include a `securityMatcher` defining exactly the requests it should intercept (the last one should be designed as default, intercepting all requests that weren't intercepted by filter chains with higher precedence). For instance, a filter chain for `Basic` auth would include such a `securityMatcher`:
```java
http.securityMatcher((HttpServletRequest request) -> {
  return Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION)).map(h -> {
    return h.toLowerCase().startsWith("basic ");
  }).orElse(false);
});
```
As the security filter chains auto-configured by `spring-addons-starter-oidc` have very low precedence (`LOWEST_PRECEDENCE` for `oauth2ResourceServer` and `LOWEST_PRECEDENCE - 1` for `oauth2Login`), **defining a security filter chain bean with `@Order(Ordered.LOWEST_PRECEDENCE - 2)` (or higher) and a `securityMatcher` is enough to add support for any other request authorization than `oauth2ResourceServer` and `oauth2Login`**.

## How to configure the authorized client manager to go through an HTTP proxy?
`(Reactive)OAuth2AuthorizedClientManager` use `(Reactive)OAuth2AuthorizedClientProvider` which internally use `RestClient` or `WebClient`. Proxy properties can be set on `WebClient.Builder::clientConnector` and `RestClient.Builder::requestFactory`. So, for the token request to go through a proxy, we need to manually configure all this beans.

Let's consider the following scenario:
- `spring.security.oauth2.client.provider.external` provider definition that out OAuth2 client can reach only through a proxy
- `spring.security.oauth2.client.registration.m2m` references this `external` provider

`spring-addons-starter-rest` greatly simplifies the configuration of a `RestClient.Builder` with proxy properties to reach the `external` provider:
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          token-client:
            expose-builder: true
            # properties below are needed only if the HTTP_PROXY and NO_PROXY environment variables are not enough
            # or to set proxy authentication
#            http:
#              proxy:
#                host: https://proxy.corporate.com:8443
```
We can now further configure this `RestClient.Builder` and configure an authorized client provider to use the resulting `RestClient` when working with the `m2m` registration
```java
// Expose a RestClient bean with:
// - spring-addons-starter-rest proxy auto-configuration
// - the message converters required by all OAuth2 token endpoints
@Bean
RestClient tokenClient(RestClient.Builder tokenClientBuilder) {
  return tokenClientBuilder.messageConverters((messageConverters) -> {
    messageConverters.clear();
    messageConverters.add(new FormHttpMessageConverter());
    messageConverters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
  }).defaultStatusHandler(new OAuth2ErrorResponseErrorHandler()).build();
}

// Replace spring-addons-starter-oidc default OAuth2AuthorizedClientProvider bean with one using a custom RestClient
// when using the "m2m" registration
@Bean
OAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider(
    SpringAddonsOidcProperties addonsProperties,
    InMemoryClientRegistrationRepository clientRegistrationRepository,
    RestClient tokenClient) {
  return new PerRegistrationOAuth2AuthorizedClientProvider(clientRegistrationRepository,
      addonsProperties, Map.of("m2m", tokenClient));
}
```
`spring-addons-starter-oidc` will detect this authorized client provider and use it instead of auto-configuring one.

## What about cookies?
With `oauth2Login`, request authorization is based on session cookies and requires protection against CSRF. In the case of single-page (Angular, React, Vue, ...) and mobile frontends, backends should expose the CSRF token as a cookie with `HttpOnly=false`, using this cookie as the CSRF token repository.

Both session and CSRF cookies should be flagged `SameSite` (`Lax` is fine) and `Secure` (a reverse proxy configured with SSL is enough, and on a dev machine, the certificate might be self-signed). The session cookie should always be `HttpOnly=true`.

The default cookies may conflict when several applications are hosted on the same host, unless we set a different name or path for each application. There is no specific restriction for session and CSRF cookie names, but we should be careful with browsers' security behavior regarding the path:
- The JavaScript from a single-page application (Angular, React, Vue, ...) can access a cookie only if it is flagged with `HttpOnly=false` and if the cookie path is a prefix for the SPA assets. If it can't read this cookie, the frontend can't read the token value and set the `X-XSRF-TOKEN` header with `POST`, `PUT`, `PATCH`, and `DELETE` requests.
- A cookie is attached to a frontend's request only if the cookie path is a prefix for the request path. If this cookie is missing, the backend generates a new one with a new CSRF token value, and the validation fails (as a reminder, the CSRF token repository is this cookie, not the session).

So, we can use as path for the CSRF cookie only what is common between the UI assets and the REST backend (for example `/foo` for `/foo/ui/**` and `/foo/bff/v1/**`). As the session cookie is never read by the frontend JavaScript, using the prefix for this backend as path for the session cookie is fine (in the preceding example, any starting fragment of `/foo/bff/v1` would work).

With Spring Boot, the session cookie can be configured with standard properties. Sample in a servlet application:
```yaml
server:
  servlet:
    session:
      cookie:
        name: X-FOO-SESSION
```

With `spring-addons-starter-oidc`, the CSRF cookie path and name can be configured if the `csrf` property is set to `cookie-accessible-from-js`:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          csrf: cookie-accessible-from-js
          csrf-cookie-name: X-FOO-CSRF
          csrf-cookie-path: /
```

## How to customize the `RestTemplate` used to fetch OpenID Configuration?
Expose a `SpringAddonsJwtDecoderFactory` bean using a customized `RestOperations`. The `DefaultSpringAddonsJwtDecoderFactory` has a constructor to ease that:
```java
@Bean
DefaultSpringAddonsJwtDecoderFactory springAddonsJwtDecoderFactory() {
  var restOperations = new RestTemplate();
  // further configuration of the RestTemplate to use during OpenID connect configuration
  // retrieval: timeouts, SSL bundles, HTTP proxy, ...
  return new DefaultSpringAddonsJwtDecoderFactory(restOperations);
}
```

