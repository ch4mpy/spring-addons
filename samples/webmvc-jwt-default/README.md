# Servlet Resource Server With JWT Decoder Using `spring-addons-webmvc-jwt-resource-server`
In this sample, we use a thin wrapper around `spring-boot-starter-oauth2-resource-server` to configure a Spring Boot 3 servlet (WebMVC) resource server using almost only application properties.

## 1. Dependencies
As usual, we'll start with http://start.spring.io/ adding the following dependencies:
- Spring Web
- Spring Boot Actuator
- Lombok

It is worth noting that, compared to [`servlet-resource-server` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-resource-server), we do not depend on `OAuth2 Resource Server`. Instead, we'll use [`spring-addons-webmvc-jwt-resource-server`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-resource-server/6.1.5), a thin wrapper around it, which pushes auto-configuration to a next level:
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-webmvc-jwt-resource-server</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
```

## 2. Application Properties
As stated in preamble, most configuration stands in properties. Let's detail what we have in yaml file.

The First part defines constants to be reused later in configuration:
```yaml
scheme: http
origins: ${scheme}://localhost:4200
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/
```

Now, the core of spring-addons configuration with:
- CORS configuration per path matcher (here we use just one matcher intercepting all the end-points processed by the resource server filter-chain)
- 3 trusted OIDC Providers (issuers) with for each:
  * `location`: the issuer URI (must be exactly the same as in access token `iss` claim). It is used to fetch OpenID configuration and resolve the authentication manager for a request
  * `username-claim`: necessary only to use something else than `sub` claim
  * `authorities`: authorities mapping configuration, for each claim to use (JSON path, case transformation and prefix)
- path matchers for resources accessible to all requests, including anonymous ones (path not matched here require users to be authenticated)
- sessions are left stateless (disabled), the default for spring-addons resource servers
- CSRF protection is left disabled, the default for spring-addons when sessions are stateless
- the spring-addons default behavior for resource server of returning 401 (unauthorized) instead of 302 (redirect to login) when authentication is missing or invalid, is kept too
```yaml
com:
  c4-soft:
    springaddons:
      security:
        cors:
        - path: /**
          allowed-origins: ${origins}
        issuers:
        - location: ${keycloak-issuer}
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - location: ${cognito-issuer}
          username-claim: username
          authorities:
          - path: cognito:groups
        - location: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: $['https://c4-soft.com/user']['roles']
          - path: $.permissions
        permit-all:
        - "/greet/public"
        - "/actuator/health/readiness"
        - "/actuator/health/liveness"
        - "/v3/api-docs/**"
```
Then follows some standard Boot configuration, for server, logging, actuator, ...:
```yaml
server:
  error:
    include-message: always
  ssl:
    enabled: false

spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s
    
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
```
Last, we have a Spring profile to enable SSL (both on our server and when talking to our local Keycloak instance):
```yaml
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

## 3. Java Configuration
As an auto-configured `SecurityFilterChain` is provided by `spring-addons-webmvc-jwt-resource-server`, we need no more than:
```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
        // @formatter:off
        return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
                .requestMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL")
                .anyRequest().authenticated();
        // @formatter:on
    }
}
```
Here, we enabled method security to fine-tune access control inside components (until now, we just had coarse rules for authenticated or not). Such rules are illustrated in `@Controller`, `@Service` and `@Repository`.

The `AuthorizeExchangeSpecPostProcessor` is there mostly for illustration purpose: demo how to write fined grained access control rules from Java configuration with spring-addons starters. It could be replaced with `@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL'))"` on `GreetingController::securedRoute`, leaving the (explicit) security configuration empty.

## 4. `@RestController`, `@Service` and `@Repository`
Really nothing special there, just standard Spring components with method security. Copy from the source if you are using this README as a tutorial to reproduce the sample.

## 5. Testing
Source code contains unit and integration testing for all access control rules. This covers `@Controller` off course, but also `@Service` and `@Repository` (the later two being impossible with OAuth2 and just `spring-security-test`). Make sure you give it an eye.

## 6. Conclusion
In this sample, we used `spring-addons-webmvc-jwt-resource-server`, a thin wrapper around `spring-boot-starter-oauth2-resource-server`, to configure a servlet (WebMVC) Spring Boot 3 resource server using possibly only application properties with:
- stateless session management
- disabled CSRF (because of disabled sessions)
- fine grained CORS configuration (and we could easily change the allowed origins when deploying to new environments)
- multi-tenancy (accept identities from several trusted OIDC Providers)
- expected HTTP status for unauthorized requests
- basic access control to fine tune with method security

Isn't it Bootiful?
