# Servlet Resource Server With JWT Decoder Using `spring-addons-starter-oidc`
In this sample, we use a thin wrapper around `spring-boot-starter-oauth2-resource-server` to configure a Spring Boot 3 servlet (WebMVC) resource server using almost only application properties.

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that sources compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Dependencies
As usual, we'll start with http://start.spring.io/ adding the following dependencies:
- Spring Web
- OAuth2 Resource Server
- Spring Boot Actuator
- Lombok

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

The first part defines constants to be reused later in configuration:
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
      oidc:
        cors:
        - path: /**
          allowed-origin-patterns: ${origins}
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
As an auto-configured `SecurityFilterChain` is provided by `spring-addons-webmvc-jwt-resource-server`.

The `AuthorizeExchangeSpecPostProcessor` we define below is there mostly for illustration purpose: demo how to write fined grained access control rules from Java configuration with `spring-addons-starter-oidc`. It could be replaced with `@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL'))"` on `GreetingController::securedRoute`, leaving the (explicit) security configuration empty.
```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig {
  @Bean
  ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
    return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
        .requestMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL")
        .anyRequest().authenticated();
  }
}
```

## 4. `@RestController`, `@Service` and `@Repository`
Really nothing special there, just standard Spring components with method security. Copy from the source if you are using this README as a tutorial to reproduce the sample.

## 5. Testing
Source code contains unit and integration testing for all access control rules. This covers `@Controller` off course, but also `@Service` and `@Repository` (the later two being impossible with OAuth2 and just `spring-security-test`). Make sure you give it an eye.

## 6. Conclusion
In this sample, we used `spring-addons-starter-oidc`, in addition to `spring-boot-starter-oauth2-resource-server`, to configure a servlet (WebMVC) Spring Boot 3 resource server using possibly only application properties with:
- stateless session management
- disabled CSRF (because of disabled sessions)
- fine-grained CORS configuration (and we could easily change the allowed origins when deploying to new environments)
- multi-tenancy (accept identities from several trusted OIDC Providers)
- expected HTTP status for unauthorized requests
- basic access control to fine tune with method security

Isn't it Bootiful?
