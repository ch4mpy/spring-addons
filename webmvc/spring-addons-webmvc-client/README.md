# `spring-addons-webmvc-client`
A thin wrapper around `spring-boot-starter-oauth2-client` which pushes auto-configuration one step further.

## How it works
As any boot starter, a resource file defines what should be loaded: [`src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-client/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports) which specifies that two configuration sources should be loaded:
- [`SpringAddonsOAuth2ClientBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-client/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/SpringAddonsOAuth2ClientBeans.java) with a bunch of OAuth2 client related beans configurable from application properties
- [`SpringAddonsBackChannelLogoutBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-client/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/SpringAddonsBackChannelLogoutBeans.java) which contains the beans definition for a client [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) implementation: a security filter-chain and a `@RestController`.

Also, as any serious Boot starter, any bean defined there is conditional, so that one way or another, you can deactivate or overload it.

## What is auto configured
The most accurate information about [`SpringAddonsOAuth2ClientBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-client/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/SpringAddonsOAuth2ClientBeans.java) and [`SpringAddonsBackChannelLogoutBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-client/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/SpringAddonsBackChannelLogoutBeans.java) is in the source and Javadoc, but here is an idea of the auto configured beans.

### SpringAddonsOAuth2ClientBeans
- `springAddonsClientFilterChain`: a security filter-chain instantiated only if `com.c4-soft.springaddons.security.client.security-matchers` property has at least one entry. If defined, it is a high precedence, to ensure that all routes defined in this security matcher property are intercepted by this filter-chain.
- `oAuth2AuthorizationRequestResolver`: default instance is a `SpringAddonsOAuth2AuthorizationRequestResolver` which sets the client hostname in the redirect URI with `com.c4-soft.springaddons.security.client.client-uri`
- `logoutRequestUriBuilder`: builder for [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) queries, taking configuration from properties for OIDC providers which do not strictly comply with the spec: logout URI not provided by OIDC conf or non standard parameter names (Auth0 and Cognito are samples of such OPs)
- `logoutSuccessHandler`: default instance is a `SpringAddonsOAuth2LogoutSuccessHandler` which logs a user out from the last authorization server he logged on
- `authoritiesConverter`: an `OAuth2AuthoritiesConverter`. Default instance is a `ConfigurableClaimSet2AuthoritiesConverter` which reads spring-addons `SpringAddonsSecurityProperties`
- `grantedAuthoritiesMapper`: a `GrantedAuthoritiesMapper` using the already configured `OAuth2AuthoritiesConverter`
- `corsConfigurationSource`: CORS configuration built from `SpringAddonsOAuth2ClientProperties`
- `oAuth2AuthorizedClientRepository`: a `SpringAddonsOAuth2AuthorizedClientRepository` (which is also a session listener) capable of handling multi-tenancy and back-channel logout
- `clientAuthorizePostProcessor`: a post processor to fine tune access control from java configuration. It applies to all routes not listed in "permit-all" property configuration. Default requires users to be authenticated. **This is a bean to provide in your application configuration if you prefer to define fine-grained access control rules with Java configuration rather than methods security.**
- `clientHttpPostProcessor`: a post processor to override anything from above auto-configuration. It is called just before the security filter-chain is returned. Default is a no-op.

### SpringAddonsBackChannelLogoutBeans
This two beans are instantiated only if `com.c4-soft.springaddons.security.client.back-channel-logout-enabled` is `true`
- `springAddonsBackChannelLogoutClientFilterChain`: a filter chain with highest precedence intercepting requests to just `/backchannel_logout`, with no session, no CSRF protection and no access-control: security is based on ly on the logout JWT in the request payload.
- `BackChannelLogoutController` a REST controller to handle just the POST requests to `/backchannel_logout` with a logout JWT provided as `application/x-www-form-urlencoded`

## Sample usage
The [resource server & UI](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui) uses this starter to configure a Spring Boot application with a client security filter-chain in addition to a resource server one configured with `spring-addons-webmvc-jwt-resource-server` starter. In this sample, the Java web-security configuration is reduced to almost nothing, all the configuration being defined with the following properties:
```yaml
api-host: ${scheme}://localhost:${server.port}
ui-host: ${api-host}
rp-initiated-logout-enabled: true

scheme: http
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
keycloak-secret: change-me
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-secret: change-me
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/
autho-secret: change-me

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
          keycloak-user:
            authorization-grant-type: authorization_code
            client-name: a local Keycloak instance
            client-id: spring-addons-confidential
            client-secret: ${keycloak-secret}
            provider: keycloak
            scope: openid,profile,email,offline_access
          keycloak-programmatic:
            authorization-grant-type: client_credentials
            client-id: spring-addons-confidential
            client-secret: ${keycloak-secret}
            provider: keycloak
            scope: openid,offline_access
          cognito-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Amazon Cognito
            client-id: 12olioff63qklfe9nio746es9f
            client-secret: ${cognito-secret}
            provider: cognito
            scope: openid,profile,email
          auth0-confidential-user:
            authorization-grant-type: authorization_code
            client-name: Auth0
            client-id: TyY0H7xkRMRe6lDf9F8EiNqCo8PdhICy
            client-secret: ${autho-secret}
            provider: auth0
            scope: openid,profile,email,offline_access

com:
  c4-soft:
    springaddons:
      security:
        cors:
        - path: /api/greet
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
          username-claim: $['https://c4-soft.com/spring-addons']['name']
          authorities:
          - path: $.roles
          - path: $.permissions
        permit-all: 
        - /actuator/health/readiness
        - /actuator/health/liveness
        - /v3/api-docs/**
        - /api/public
        client:
          security-matchers:
          - /login/**
          - /oauth2/**
          - /
          - /ui/**
          - /swagger-ui/**
          permit-all:
          - /login/**
          - /oauth2/**
          - /
          - /ui/
          - /swagger-ui.html
          - /swagger-ui/**
          client-uri: ${ui-host}
          post-login-redirect-path: /ui/greet
          post-logout-redirect-path: /ui/greet
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
        
logging:
  level:
    org:
      springframework:
        security: DEBUG
            
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

---
scheme: https
keycloak-port: 8443

server:
  ssl:
    enabled: true

spring:
  config:
    activate:
      on-profile: ssl
```