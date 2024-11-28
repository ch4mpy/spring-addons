# Reactive Resource Server With JWT Decoder Using `spring-addons-webflux-jwt-resource-server`
In this sample, we use a thin wrapper around `spring-boot-starter-oauth2-resource-server` to configure a Spring Boot 3 reactive (WebFlux) resource server using almost only application properties.

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that sources compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Dependencies
As usual, we'll start with http://start.spring.io/ adding the following dependencies:
- Spring Reactive Web
- OAuth2 Resource Server
- Spring Boot Actuator
- lombok

Then add dependencies to spring-addons:
- [`spring-addons-starter-oidc`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-starter-oidc)
- [`spring-addons-starter-oidc-test`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-starter-oidc-test) with `test` scope
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc-test</artifactId>
    <version>${spring-addons.version}</version>
    <scope>test</scope>
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
      oidc:
        ops:
        - iss: ${keycloak-issuer}
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - iss: ${cognito-issuer}
          username-claim: username
          authorities:
          - path: cognito:groups
        - iss: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: $['https://c4-soft.com/user']['roles']
          - path: $.permissions
        resourceserver:
          permit-all:
          - "/greet/public"
          - "/actuator/health/readiness"
          - "/actuator/health/liveness"
          - "/v3/api-docs/**"
```

## 3. Java Configuration
An auto-configured `SecurityWebFilterChain` is provided by `spring-addons-webflux-jwt-resource-server`.

When using just method security, no additional conf is needed. But for demonstration puposes we'll demo how to add access control in Java conf:
```java
@EnableReactiveMethodSecurity()
@Configuration
public class SecurityConfig {
  @Bean
  ResourceServerAuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor() {
    return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec
        .pathMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL")
        .anyExchange().authenticated();
  }
}
```

## 4. `@RestController`, `@Service` and `@Repository`
Really nothing special there, just standard Spring components with method security. Copy from the source if you are using this README as a tutorial to reproduce the sample.

## 5. Testing
Source code contains unit and integration testing for all access control rules. This covers `@Controller` off course, but also `@Service` and `@Repository` (the later two being impossible with OAuth2 and just `spring-security-test`). Make sure you give it an eye.

## 6. Conclusion
In this sample, we used `spring-addons-webflux-jwt-resource-server`, a thin wrapper around `spring-boot-starter-oauth2-resource-server`, to configure a reactive (WebFlux) Spring Boot 3 resource server using possibly only application properties with:
- stateless session management
- disabled CSRF (because of disabled sessions)
- multi-tenancy (accept identities from several trusted OIDC Providers)
- expected HTTP status for unauthorized requests
- basic access control to fine tune with method security

Isn't it Bootiful?
