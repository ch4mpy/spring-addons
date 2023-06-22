# `spring-addons-webflux-client`
A thin wrapper around `spring-boot-starter-oauth2-client` which pushes auto-configuration one step further.

## How it works
As any boot starter, a resource file defines what should be loaded: [`src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`](https://github.com/ch4mpy/spring-addons/blob/master/webflux/spring-addons-webflux-client/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports) which specifies that two configuration sources should be loaded:
- [`SpringAddonsOAuth2ClientBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webflux/spring-addons-webflux-client/src/main/java/com/c4_soft/springaddons/security/oauth2/config/reactive/SpringAddonsOAuth2ClientBeans.java) with a bunch of OAuth2 client related beans configurable from application properties
- [`SpringAddonsBackChannelLogoutBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webflux/spring-addons-webflux-client/src/main/java/com/c4_soft/springaddons/security/oauth2/config/reactive/SpringAddonsBackChannelLogoutBeans.java) which contains the beans definition for a client [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) implementation: a security filter-chain and a `@RestController`.

Also, as any serious Boot starter, any bean defined there is conditional, so that one way or another, you can deactivate or overload it.

## What is auto configured
The most accurate information about [`SpringAddonsOAuth2ClientBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webflux/spring-addons-webflux-client/src/main/java/com/c4_soft/springaddons/security/oauth2/config/reactive/SpringAddonsOAuth2ClientBeans.java) and [`SpringAddonsBackChannelLogoutBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webflux/spring-addons-webflux-client/src/main/java/com/c4_soft/springaddons/security/oauth2/config/reactive/SpringAddonsBackChannelLogoutBeans.java) is in the source and Javadoc, but here is an idea of the auto configured beans.

### SpringAddonsOAuth2ClientBeans
All the beans below are `@ConditionalOnMissingBean`, with an exception of the first which is conditional on a property. This means that you keep complete control: if you define a bean of the same type as any of the following, your definition will replace the one from this starter.
- `springAddonsClientFilterChain`: a security filter-chain instantiated only if `com.c4-soft.springaddons.security.client.security-matchers` property has at least one entry. If defined, it is a high precedence, to ensure that all routes defined in this security matcher property are intercepted by this filter-chain. Refer to [`SpringAddonsOAuth2ClientProperties`](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-oauth2/src/main/java/com/c4_soft/springaddons/security/oauth2/config/SpringAddonsOAuth2ClientProperties.java) for configuration options. Mind the optional properties, and `login-path` in particular: if you provide one, you'll also have to provide with a &#64;Controller to handle it.
- `logoutRequestUriBuilder`: builder for [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) queries, taking configuration from properties for OIDC providers which do not strictly comply with the spec: logout URI not provided by OIDC conf or non standard parameter names (Auth0 and Cognito are samples of such OPs)
- `serverLogoutSuccessHandler`: default instance is a `SpringAddonsOAuth2ServerLogoutSuccessHandler` which logs a user out from the last authorization server he logged on
- `authoritiesConverter`: an `OAuth2AuthoritiesConverter`. Default instance is a `ConfigurableClaimSet2AuthoritiesConverter` which reads spring-addons `SpringAddonsSecurityProperties`
- `grantedAuthoritiesMapper`: a `GrantedAuthoritiesMapper` using the already configured `OAuth2AuthoritiesConverter`
- `oAuth2AuthorizedClientRepository`: a `SpringAddonsServerOAuth2AuthorizedClientRepository` (which is also a session listener) capable of handling multi-tenancy and back-channel logout
- `clientAuthorizePostProcessor`: a post processor to fine tune access control from java configuration. It applies to all routes not listed in "permit-all" property configuration. Default requires users to be authenticated. **This is a bean to provide in your application configuration if you prefer to define fine-grained access control rules with Java configuration rather than methods security.**
- `clientHttpPostProcessor`: a post processor to override anything from above auto-configuration. It is called just before the security filter-chain is returned. Default is a no-op.
- `csrfCookieWebFilter`: a `WebFilter` to set the CSRF cookie if `com.c4-soft.springaddons.security.client.csrf` is set with one of the two cookie options
- `webSessionManager` with a custom `webSessionStore` which is a proxy of `InMemoryWebSessionStore` on which `WebSessionListener` can register to be notified with sessions `create` and `remove` event

### SpringAddonsBackChannelLogoutBeans
This two beans are instantiated only if `com.c4-soft.springaddons.security.client.back-channel-logout-enabled` is `true`
- `springAddonsBackChannelLogoutClientFilterChain`: a filter chain with highest precedence intercepting requests to just `/backchannel_logout`, with no session, no CSRF protection and no access-control: security is based on ly on the logout JWT in the request payload.
- `BackChannelLogoutController` a REST controller to handle just the POST requests to `/backchannel_logout` with a logout JWT provided as `application/x-www-form-urlencoded`

## Sample usage
The [BFF tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/bff) uses this starter to configure a `spring-cloud-gateway` instance as an OAuth2 client with Back-Channel Logout. In this sample, the Java web-security configuration is reduced to nothing, all the configuration being defined with the following properties:
```yaml
scheme: http
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
keycloak-secret: change-me
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-secret: change-me
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/
auth0-secret: change-me

gateway-uri: ${scheme}://localhost:${server.port}
greetings-api-uri: ${scheme}://localhost:6443/greetings
angular-uri: ${scheme}://localhost:4200

server:
  port: 8080
  ssl:
    enabled: false


spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s
  security:
    oauth2:
      client:
        provider:
          keycloak:
            issuer-uri: ${keycloak-issuer}
          cognito:
            issuer-uri: ${cognito-issuer}
          auth0:
            issuer-uri: ${auth0-issuer}
        registration:
          keycloak-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Keycloak
            client-id: spring-addons-confidential
            client-secret: ${keycloak-secret}
            provider: keycloak
            scope: openid,profile,email,offline_access,roles
          cognito-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Cognito
            client-id: 12olioff63qklfe9nio746es9f
            client-secret: ${cognito-secret}
            provider: cognito
            scope: openid,profile,email
          auth0-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Auth0
            client-id: TyY0H7xkRMRe6lDf9F8EiNqCo8PdhICy
            client-secret: ${auth0-secret}
            provider: auth0
            scope: openid,profile,email,offline_access
  cloud:
    gateway:
      default-filters:
      - TokenRelay=
      - DedupeResponseHeader=Access-Control-Allow-Credentials Access-Control-Allow-Origin
      - SaveSession
      - SecureHeaders
      routes:
      - id: greetings
        uri: ${greetings-api-uri}
        predicates:
        - Path=/greetings/**
      - id: ui
        uri: ${angular-uri}
        predicates:
        - Path=/ui/**
      - id: home
        uri: ${angular-uri}
        predicates:
        - Path=/
        filters:
        - RewritePath=/,/ui

com:
  c4-soft:
    springaddons:
      security:
        issuers:
        - location: ${keycloak-issuer}
          username-claim: $.preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - location: ${cognito-issuer}
          username-claim: $.username
          authorities:
          - path: $.cognito:groups
        - location: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: $['https://c4-soft.com/user']['roles']
          - path: $.permissions
        client:
          client-uri: ${gateway-uri}
          security-matchers: /**
          permit-all:
          - /login/**
          - /oauth2/**
          - /
          - /login-options
          - "/me"
          - /ui/**
          - /v3/api-docs/**
          csrf: cookie-accessible-from-js
          login-path: /ui/
          post-login-redirect-path: /ui/
          post-logout-redirect-path: /ui/
          back-channel-logout-enabled: true
          oauth2-logout:
            - client-registration-id: cognito-confidential-user
              uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: logout_uri
            - client-registration-id: auth0-confidential-user
              uri: ${auth0-issuer}v2/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: returnTo
          authorization-request-params:
            auth0-confidential-user:
              - name: audience
                value: https://bff.demo.c4-soft.com
            
management:
  endpoint:
    health:
      probes:
        enabled: true
  endpoints:
    web:
      exposure:
        include: '*'
  health:
    livenessstate:
      enabled: true
    readinessstate:
      enabled: true

logging:
  level:
    root: ERROR
    org.springframework.security: DEBUG
    
---
spring:
  config:
    activate:
      on-profile: ssl

server:
  ssl:
    enabled: true

scheme: https
keycloak-port: 8443
```