# Ease OAuth2 / OpenID Configuration & Tests in Spring Boot 3 

## What's new in the `8.x` branch

`8.0.0-RC1`, is out. It is designed to work with Spring Boot `3.4.0-RC1`, Security `6.4.0-RC1`, and Cloud `2024.0.0-M2`.

#### `spring-addons-starter-rest`
`RestClient` & `WebClient` instances or builders can be exposed as named beans. What can be auto-configured with application properties:
- base URI
- `Basic` or `Bearer` authorization. For the second, with a choice of using an OAuth2 client registration or forwarding the access token in the security context.
- connection & read timeouts
- HTTP or SOCKS proxy, with consideration of the standard `HTTP_PROXY` and `NO_PROXY` environment variables (finer-grained configuration can be applied with custom properties)
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          machin-client:
            base-url: http://localhost:${machin-api-port}
            authorization:
              oauth2:
                forward-bearer: true
          bidule-client:
            base-url: http://localhost:${bidule-api-port}
            expose-builder: true
            authorization:
              oauth2:
                oauth2-registration-id: bidule-registration
```
This exposes two beans that we can use for instance to generate `@HttpExchange` implementations as follows (mind the `expose-builder: true` for `bidule-client`):
```java
@Configuration
public class RestConfiguration {

  @Bean
  BiduleApi biduleApi(RestClient.Builder biduleClientBuilder) throws Exception {
    return new RestClientHttpExchangeProxyFactoryBean<>(BiduleApi.class, biduleClientBuilder.build()).getObject();
  }


  @Bean
  MachinApi machinApi(RestClient machinClient) throws Exception {
    return new RestClientHttpExchangeProxyFactoryBean<>(MachinApi.class, machinClient).getObject();
  }
}
```

#### `spring-addons-starter-oidc`
- Working [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) for OAuth2 clients with `oauth2Login` (at last :/). If you don't know about Back-Channel Logout, it is some sort of *"single sign-out"* for systems with *Single Sign On* (SSO). Keycloak is a sample of an OpenID Provider capable of emitting Back-Channel Logout events to a Spring client - like a Gateway used as an OAuth2 BFF - when a user logs out from the authorization server **using another client**. This feature is disabled by default. The default internal logout URI and session cookie name can be overridden in the properties:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          back-channel-logout:
            enabled: true
            # Those two are optional, defaults should work in most scenarios
            internal-logout-uri: ${gateway-uri}/logout/connect/back-channel/quiz-bff
            cookie-name: JSESSION-ID
```
- The status for unauthorized requests can now be configured in the properties for clients with `oauth2Login`. The default is still `302 Found` (redirect to login), but we can now change it to `401 Unauthorized` (Gateway for single page or mobile applications, stateful REST APIs, ...):
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          oauth2-redirections:
            authentication-entry-point: UNAUTHORIZED
```
- `OAuthentication` now extends `AbstractOAuth2TokenAuthenticationToken`. This makes integrating with the rest of the Spring Security ecosystem easier but requires its `principal` to implement `OAuth2Token`. Migration guide:
  - if using `OpenidClaimSet` directly, wrap it in an `OpenidToken`; if extending it, extend `OpenidToken` instead.
  - move the token string argument from the `OAuthentication` constructor to the `OpenidClaimSet` one (or whatever is used as `principal`)
```java
new OAuthentication<>(new OpenidClaimSet(claims), authorities, tokenString);
```
becomes
```java
new OAuthentication<>(new OpenidToken(new OpenidClaimSet(claims), tokenString), authorities);
```

## OIDC starters

### [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc)

Reduce Java Security conf to 0 in scenarios like:
- accepting tokens issued by several trusted authorization servers
- having per environment CORS configuration (not allowing the same origins in staging and prod for instance)
- mapping authorities from a variety of claims, with custom prefix and case
- customizing OAuth2 redirection URI or HTTP status
- exposing CSRF token as a cookie accessible to a single-page application
- logging out from an authorization server not strictly implementing RP-Initiated Logout (case of Auth0 and Amazon Cognito for instance)
- activating and configuring Back-Channel Logout in a Spring application with `oauth2Login`
- adding extra parameters to authorization or token requests (like the `audience` required by Auth0)

### [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest)

Configure declarative REST clients with `Bearer` or `Basic` authorization, and HTTP proxy settings with just properties. For OAuth2 authorization, we have a choice of using a new token using any Spring OAuth2 client `registration`, or to re-use the access token in the security context of an `oauth2ResourceServer`.

For instance, to get an implementation for the following `@HttpExchange` with OAuth2 authorization:
```java
@HttpExchange(accept = MediaType.APPLICATION_JSON_VALUE)
public interface KeycloakAdminApi {

    @GetExchange(url = "/{realm}/users/count")
    Long getTotalUsersCount(@PathVariable(name = "realm") String realm);
}
```
This can be enough:
```java
@Bean
KeycloakAdminApi keycloakAdminApi(SpringAddonsRestClientSupport restSupport) {
    return restSupport.service("keycloak-admin-api", KeycloakAdminApi.class);
}
```
```yaml
keycloak-base-uri: https://localhost:8443/auth

com:
  c4-soft:
    springaddons:
      rest:
        client:
          keycloak-admin-api:
            base-url: ${keycloak-base-uri}/admin/realms
            authorization:
              oauth2:
                forward-bearer: true
```
See [the stater README](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest) for a sample with an OAuth2 client `registration` using `client_credentials`, or to get pre-configured `RestClient` & `WebClient` builders if not using `@HttpExchange` proxies.

## Unit & Integration Testing With Security

Testing access control requires to configure the test security context.  For that, `spring-security-test` provides with `MockMvc` request post-processors and `WebTestClient` mutators, but this can work only in the context of a request, which limits its usage to controllers.

To test any type of `@Component` (`@Controller`, off course, but also `@Service` and `@Repository`) there are  only two options:
- build tests security context by yourself and populate it with stubbed / mocked authentications
- use annotations to do it for you (this is where [spring-addons-oauth2-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) jumps in)

Useful resources:
- [spring-addons-oauth2-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) contains tests annotations and its README documents usage
- [spring-addons-starter-oidc-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc-test) if you use `spring-addons-starter-oidc`
- [Baeldung article](https://www.baeldung.com/spring-oauth-testing-access-control)
- [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) and [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) source-code (which contain a lot of unit and integration testing)

## Useful links
- [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc) a Spring Boot starter pushing OAuth2 clients & resource server security auto-configuration to the next level
- [`spring-addons-oauth2-test`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) annotations for populating test security-context with OAuth2 authentication instances
- [`spring-addons-starter-oidc-test`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc-test) ease unit-tests in applications using `spring-addons-starter-oidc`
- [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest) experimental auto-configuration for `RestClient`, `WebClient` and `@HttpExchange` proxies (base-URL, Basic & OAuth2 Bearer auth)
- [Getting started with Keycloak & Spring Boot](https://www.baeldung.com/spring-boot-keycloak)
- [OAuth2 security configuration tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#securing-spring-applications-with-oauth2) (with and without `spring-addons-starter-oidc`)
- [OAuth2 BFF tutorial](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2)
- [Release Notes](https://github.com/ch4mpy/spring-addons/tree/master/release-notes.md)
- [Maven-Central Reminders](https://github.com/ch4mpy/spring-addons/tree/master/maven-central.md)
