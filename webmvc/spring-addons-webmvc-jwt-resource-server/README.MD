# `spring-addons-webmvc-jwt-resource-server`
A thin wrapper around `spring-boot-starter-oauth2-client` which pushes auto-configuration one step further for servlet resource servers using JWT decoders.

## How it works
As any boot starter, a resource file defines what should be loaded: [`src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports) which specifies that two configuration sources should be loaded:
- [`AddonsSecurityBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/AddonsSecurityBeans.java) with a single `OAuth2AuthoritiesConverter` (an alias for `Converter<Map<String, Object>, Collection<? extends GrantedAuthority>>`)
- [`AddonsWebSecurityBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/AddonsWebSecurityBeans.java) which contains a few other beans involved in the creation of a security filter chain for a multi-tenant ready resource server using JWT decoder(s).

Also, as any serious Boot starter, any bean defined there is conditional, so that one way or another, you can deactivate or overload it, with one notable exception: the `springAddonsResourceServerSecurityFilterChain` is not conditional and instantiated in any case (with lowest precedence) if you depend on this starter.

## What is auto configured
The most accurate information about [`AddonsWebSecurityBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/AddonsWebSecurityBeans.java) and [`AddonsSecurityBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/AddonsSecurityBeans.java) is in the source and Javadoc, but here is an idea of the auto configured beans.

### AddonsSecurityBeans
Provides with an `authoritiesConverter` which is an instance of `ConfigurableClaimSet2AuthoritiesConverter`. This bean is configured with application properties and is able to map spring-security authorities from any claims with prefix and case transformation defined for each claim.

### AddonsWebSecurityBeans
Provides with a (non conditional) security filter-chain as well as (conditional) defaults for all the beans required to configure it:
- `springAddonsResourceServerSecurityFilterChain`: applies CORS, CSRF, anonymous, sessionCreationPolicy, SSL, redirect and 401 instead of redirect to login as defined in [`SpringAddonsSecurityProperties`](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-oauth2/src/main/java/com/c4_soft/springaddons/security/oauth2/config/SpringAddonsSecurityProperties.java)
- `authorizePostProcessor`: a bean of type `ExpressionInterceptUrlRegistryPostProcessor` to fine tune access control from java configuration. It applies to all routes not listed in "permit-all" property configuration. Default requires users to be authenticated. **This is a bean to provide in your application configuration if you prefer to define fine-grained access control rules with Java configuration rather than methods security.**
- `httpPostProcessor`: a bean of type `HttpSecurityPostProcessor` to override anything from above auto-configuration. It is called just before the security filter-chain is returned. Default is a no-op.
- `jwtAuthenticationConverter`: a converter from a `Jwt` to something inheriting from `AbstractAuthenticationToken`. The default instantiate a `JwtAuthenticationToken` with username and authorities as configured for the issuer of thi token. The easiest to override the type of `AbstractAuthenticationToken`, is to provide with an `OAuth2AuthenticationFactory` bean.
- `authenticationManagerResolver`: to accept identities issued by more than a single OP, the recommended way is to provide an `JwtIssuerAuthenticationManagerResolver` supporting it. Default keeps a `JwtAuthenticationProvider` with its own `JwtDecoder` for each issuer.

## Usage
Please take time to browse [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) and [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples).

All you need is declare a dependency on `spring-addons-webmvc-jwt-resource-server` and define a few properties.

You might use any OIDC Provider (including Keycloak, Auth0, Cognito, etc.).

``` xml
<dependencies>
    <dependency>
        <groupId>com.c4-soft.springaddons</groupId>
        <artifactId>spring-addons-webmvc-jwt-resource-server</artifactId>
        <version>${com.c4-soft.springaddons.version}</version>
    </dependency>
</dependencies>
```
``` java
@SpringBootApplication
public class SampleApi {
    public static void main(String[] args) {
        new SpringApplicationBuilder(SampleApi.class).web(WebApplicationType.SERVLET).run(args);
    }

    @Configuration
    @EnableMethodSecurity
    public static class WebSecurityConfig {
    }
}
```
```yaml
scheme: http
origins: ${scheme}://localhost:4200
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
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
          username-claim: $['https://c4-soft.com/spring-addons']['name']
          authorities:
          - path: roles
          - path: permissions
        permit-all:
        - "/greet/public"
        - "/actuator/health/readiness"
        - "/actuator/health/liveness"
        - "/v3/api-docs/**"
        
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
