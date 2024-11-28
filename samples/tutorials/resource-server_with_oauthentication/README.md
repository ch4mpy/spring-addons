# How to configure a Spring REST API with `OAuthentication<OpenidClaimSet>`
The aim here is to set up security for a Spring Boot 3 resource server with JWT decoding and a custom `Authentication` implementation instead of the default `JwtAuthenticationToken`

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that sources compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Prerequisites
We assume that [tutorials main README prerequisites section](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#prerequisites) has been achieved and that you have a minimum of 1 OIDC Provider (2 would be better) with ID and secret for clients configured with authorization-code flow.

Also, we will be using `spring-addons-starter-oidc`. If for whatever reason you don't want to do so, you'll have to follow the [`servlet-resource-server` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-resource-server) to configure the REST API as an OAuth2 resource server with just `spring-boot-starter-oauth2-resource-server`

## 2. Project Initialization
We'll start a spring-boot 3 project with the help of https://start.spring.io/
Following dependencies will be needed:
- Spring Web
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

## 3. Web-Security Configuration
`spring-oauth2-addons` comes with `@AutoConfiguration` for web-security config adapted to REST API projects. We'll just add:
- `@EnableMethodSecurity` to activate `@PreAuthorize` on components methods.
- provide a `JwtAbstractAuthenticationTokenConverter` bean to switch `Authentication` implementation from `JwtAuthenticationToken` to `OAuthentication<OpenidClaimSet>`
```java
@Bean
JwtAbstractAuthenticationTokenConverter authenticationConverter(
    Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
    OpenidProviderPropertiesResolver opPropertiesResolver) {
  return jwt -> {
    final var opProperties = opPropertiesResolver.resolve(jwt.getClaims())
        .orElseThrow(() -> new NotAConfiguredOpenidProviderException(jwt.getClaims()));
    final var accessToken =
        new OpenidToken(new OpenidClaimSet(jwt.getClaims(), opProperties.getUsernameClaim()),
            jwt.getTokenValue());
    final var authorities = authoritiesConverter.convert(jwt.getClaims());
    return new OAuthentication<>(accessToken, authorities);
  };
}
```
Here, we kept `spring-addons` default authorities converter in charge of extracting Spring authorities from token claims. This converter needs configuration properties resolved by an `OpenidProviderPropertiesResolver` (`spring-addons` default one resolves properties using by matching the token `iss` claim with the `iss` property in YAML.

## 4. Application Properties
Most security configuration is controlled from properties. Please refer to [spring-addons starter introduction tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-resource-server) for the details about the properties we set here:
```yaml
scheme: http
origins: ${scheme}://localhost:4200
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
keycloak-secret: change-me
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/

server:
  error:
    include-message: always
  ssl:
    enabled: false

spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s

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
          - "/actuator/health/readiness"
          - "/actuator/health/liveness"
          - "/v3/api-docs/**"
          - "/swagger-ui/**"

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

## 5. Sample `@RestController`
Please note that OpenID standard claims are typed and can be accessed with getters (instead of Map<String, Object> like with JwtAuthenticationToken for instance)
``` java
@RestController
@PreAuthorize("isAuthenticated()")
public class GreetingController {

    @GetMapping("/greet")
    public MessageDto getGreeting(OAuthentication<OpenidClaimSet> auth) {
        return new MessageDto("Hi %s! You are granted with: %s and your email is %s."
                .formatted(auth.getName(), auth.getAuthorities(), auth.getClaims().getEmail()));
    }

    @GetMapping("/nice")
    @PreAuthorize("hasAuthority('NICE')")
    public MessageDto getNiceGreeting(OAuthentication<OpenidClaimSet> auth) {
        return new MessageDto("Dear %s! You are granted with: %s."
                .formatted(auth.getName(), auth.getAuthorities()));
    }

    static record MessageDto(String body) {
    }
}
```

## 5. Unit-Tests
Please refer to the source code and the dedicated [article on Baeldung](https://www.baeldung.com/spring-oauth-testing-access-control)

## 6. Conclusion
This sample was guiding you to build a servlet application (webmvc) with JWT decoder and `OAuthentication<OpenidClaimSet>`. If you need help to configure a resource server for webflux (reactive)  or access token introspection or another type of authentication, please refer to other tutorials and [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples).
