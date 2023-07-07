# How to configure a Spring REST API with token introspection

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that source compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Overview
The aim here is to setup security for a Spring Boot 3 resource server access token introspection on **any OpenID authorization-server**: those exposing an introspection endpoint in their OpenID configuration (like Keycloak), but also those just exposing a `/userinfo` endpoint (like Auth0 and Amazon Cognito).

For each and every request it process, resource servers will send a request to authorization-server to get token details. This has **serious performance impact** compared to JWT-decoder based security where authorization-server is accessed only once to retrieve signing key.

## 2. Authorization-server requirements
We assume that [tutorials prerequisites](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/README.md#prerequisites) are satisfied and that a minimum of 1 OIDC Provider is configured with a client and authorization-code to authenticate users. As it is hard to guess from which OP was issued an opaque token, we will accept identities from only one issuer. To provide with multi-tenancy and token introspection, we would need a custom header or something containing the issuer URI, for our resource server to know where it should introspect it. This additional complexity is out of the scope of this tutorial and, instead, we'll work with profiles to switch between OPs.

Introspection endpoint is reached using client-credentials flow. A client should be configured with that flow too on each OP conforming with the introspection specification (either the same client as for user authentication or another one).

For Keycloak, this means a client must be configured with:
- `confidential` "Access Type"
- "Service Accounts Enabled" activated
Create one if you don't have yet. You'll get client-secret from "credentials tab" once configuration saved.

As Auth0 and Amazon Cognito do not expose an `introspection_endpoint` in their OpenID configuration, the client with client-credentials flow is not necessary there: we'll query the `/userinfo` endpoint using the access token to introspect as access token for that request.

## 3. Project Initialization
We'll start a spring-boot 3 project with the help of https://start.spring.io/
Following dependencies will be needed:
- Lombok

Then add dependencies to spring-addons:
- [`spring-addons-webmvc-jwt-resource-server`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-resource-server/6.1.5)
- [`spring-addons-webmvc-jwt-test`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-test/6.1.5) with `test` scope
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <!-- use spring-addons-webflux-jwt-resource-server instead for reactive apps -->
    <artifactId>spring-addons-webmvc-introspecting-resource-server</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <!-- use spring-addons-webflux-test instead for reactive apps -->
    <artifactId>spring-addons-webmvc-introspecting-test</artifactId>
    <version>${spring-addons.version}</version>
    <scope>test</scope>
</dependency>
```

If for whatever reason you don't want to use spring-addons starters, see [`servlet-resource-server`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-resource-server) or [`reactive-resource-server`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/reactive-resource-server) for basic configuration with `spring-boot-starter-oauth2-resource-server`. Spoiler, it is quite more verbose and error prone.

## 5. Application Properties
Let's first define some constants later used in configuration, and sometimes overriden in profiles:
```yaml
scheme: http
origins: ${scheme}://localhost:4200
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
keycloak-secret: change-me
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-secret: change-me
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/
auth0-secret: change-me
```
Then we have some standard Spring Boot configuration for the server and OAuth2 resource servers with token introspection:
```yaml
server:
  error:
    include-message: always
  ssl:
    enabled: false
spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          client-id: spring-addons-confidential
          client-secret: ${keycloak-secret}
          introspection-uri: ${keycloak-issuer}/protocol/openid-connect/token/introspect
```
Next is some spring-addons configuration with:
- CORS configuration (enables for instance to switch allowed-origins when deploying to a new environment)
- `issuers`: provide with authorities mapping configuration (claim(s) to pick, as well as case and prefix transformations)
- `permit-all`: path matchers for "public" resources (accessible to unauthorized requests). Path not matched here require requests to be authorized (access control fine tuned with method security)
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
        permit-all: 
        - "/actuator/health/readiness"
        - "/actuator/health/liveness"
        - "/v3/api-docs/**"
```
Last is profile to enable SSL on this server and when talking to the local Keycloak instance:
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

## 4. Web-Security Configuration
`spring-addons-webmvc-introspecting-resource-server` auto-configures a security filter-chain for resource server with token introspection and there is nothing we have to do beyond activating method security.

Optionally, we can switch the type of `Authentication` at runtime by providing an`OpaqueTokenAuthenticationConverter`. To press on the fact that this bean is not mandatory, we'll activate it with a profile:
```java
@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {

    @Bean
    @Profile("oauthentication")
    //This bean is optional as a default one is provided (building a BearerTokenAuthentication)
    OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
        return (String introspectedToken,
                OAuth2AuthenticatedPrincipal authenticatedPrincipal) -> new OAuthentication<>(
                        new OpenidClaimSet(authenticatedPrincipal.getAttributes()),
                        authoritiesConverter.convert(authenticatedPrincipal.getAttributes()),
                        introspectedToken);
    }
}
```
The reasons why we could prefer `OAuthentication<OpenidClaimSet>` over `BearerTokenAuthentication` are its improved API to access OpenID claims and its versatility (compatible with JWT decoding too).

## 6. Non-Standard Introspection Endpoint
The token introspection we have works just fine with OIDC Providers exposing an `introspection_endpoint` in their OpenID configuration (like Keycloak does), but some just don't provide one (like Auth0 and Amazon Cognito). Hopefully, almost any OP exposes a `/userinfo` endpoint returning the OpenID claims of the user for whom was issued the access token in the Authorization header.

### 6.1. Additional Application Properties
Let's first define spring profiles with `introspection-uri` setted with userinfo URI for the OPs without an `introspection_endpoint`:
```yaml
---
com:
  c4-soft:
    springaddons:
      security:
        issuers:
        - location: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: $['https://c4-soft.com/user']['roles']
          - path: $.permissions
spring:
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          client-id: TyY0H7xkRMRe6lDf9F8EiNqCo8PdhICy
          client-secret: ${auth0-secret}
          introspection-uri: ${auth0-issuer}userinfo
  config:
    activate:
      on-profile: auth0
---
com:
  c4-soft:
    springaddons:
      security:
        issuers:
        - location: ${cognito-issuer}
          username-claim: $.username
          authorities:
          - path: $.cognito:groups
spring:
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          client-id: 12olioff63qklfe9nio746es9f
          client-secret: ${cognito-secret}
          introspection-uri: https://spring-addons.auth.us-west-2.amazoncognito.com/oauth2/userInfo
  config:
    activate:
      on-profile: cognito
```

### 6.2. Custom `OpaqueTokenIntrospector`
Now, we can write our own `OpaqueTokenIntrospector`, querying `/userinfo` with an Authorization header containing the token to introspect. If we get an answer, the token is valid and the claims will be the OpenID claims of the user for whom this token was issued:
```java
@Component
@Profile("auth0 | cognito")
public static class UserEndpointOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
    private final URI userinfoUri;
    private final RestTemplate restClient = new RestTemplate();

    public UserEndpointOpaqueTokenIntrospector(OAuth2ResourceServerProperties oauth2Properties)
            throws IOException {
        userinfoUri = URI.create(oauth2Properties.getOpaquetoken().getIntrospectionUri());
    }

    @Override
    @SuppressWarnings("unchecked")
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        final var claims = new OpenidClaimSet(restClient
                .exchange(userinfoUri, HttpMethod.GET, new HttpEntity<>(headers), Map.class).getBody());
        // No need to map authorities there, it is done later by OpaqueTokenAuthenticationConverter
        return new OAuth2IntrospectionAuthenticatedPrincipal(claims, List.of());
    }

}
```

## 7. Sample `@RestController`
``` java
@RestController
@RequestMapping("/greet")
public class GreetingController {

    @GetMapping()
    @PreAuthorize("hasAuthority('NICE')")
    public MessageDto getGreeting(Authentication auth) {
        return new MessageDto("Hi %s! You are granted with: %s.".formatted(
                auth.getName(),
                auth.getAuthorities()));
    }

    static record MessageDto(String body) {
    }
}
```

## 8. Conclusion
In this tutorial, we configured a Spring Boot 3 resource server with access token introspection on about any OpenID authorization-server, including those not exposing an `introspection_endpoint` in their `.well-known/openid-configuration`: we used the `/userinfo` endpoint (which almost always exists) and a custom `OpaqueTokenIntrospector` for such OPs.