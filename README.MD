# Ease OAuth2 / OpenID Configuration & Tests in Spring Boot 3 

## What's new in the `8.x` branch

`8.0.0-RC1`, is out. It is designed to work with Spring Boot `3.4.0-RC1`, Security `6.4.0-RC1`, and Cloud `2024.0.0-M2`.

- `spring-addons-starter-rest` is gaining in maturity. It can now expose as `@Bean` some `RestClient` and `WebClient` instances (or builders) with the following configured using application properties:
  - Base URI
  - `Basic` or `Bearer` authorization. For the second, with a choice of using an OAuth2 client registration or forwarding the access token in the security context.
  - Connection & read timeouts
  - HTTP or SOCKS proxy, with consideration of the standard `HTTP_PROXY` and `NO_PROXY` environment variables (finer-grained configuration can be applied with custom properties)
- `spring-addons-starter-oidc` auto-configuration for `oauth2Login` is improved with:
  - Working [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) (at last :/).
  - The status for unauthorized requests can now be configured in the properties for clients with `oauth2Login`. The default is still `302 Found` (redirect to login), but it's a snap to change it to `401 Unauthorized` (BFF for single page or mobile applications, stateful REST APIs, ...).
- `OAuthentication` now extends `AbstractOAuth2TokenAuthenticationToken`. This makes integrating with the rest of the Spring Security ecosystem easier but requires its `principal` to implement `OAuth2Token`. Migration guide:
  - if using `OpenidClaimSet` directly, wrap it in an `OpenidToken`; if extending it, extend `OpenidToken` instead.
  - move the token string argument from the `OAuthentication` constructor to the `principal` one (`OpenidToken` by default)
```java
new OAuthentication<>(new OpenidClaimSet(claims), authorities, tokenString);
```
becomes
```java
new OAuthentication<>(new OpenidToken(new OpenidClaimSet(claims), tokenString), authorities);
```

## [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc)

A spring Boot starter to reduce Java Security conf to 0 in scenarios like:
- accepting tokens issued by several trusted authorization servers
- having per environment CORS configuration (not allowing the same origins in staging and prod for instance)
- mapping authorities from a variety of claims, with custom prefix and case
- customizing OAuth2 redirection URI or HTTP status
- exposing CSRF token as a cookie accessible to a single-page application
- logging out from an authorization server not strictly implementing RP-Initiated Logout (case of Auth0 and Amazon Cognito for instance)
- activating and configuring Back-Channel Logout in a Spring application with `oauth2Login`
- adding extra parameters to authorization or token requests (like the `audience` required by Auth0)

## [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest)

A spring Boot starter to expose REST clients auto-configured with requests authorization, HTTP proxy settings, and more. For OAuth2 authorization, we have a choice of using a new token using any Spring OAuth2 client `registration`, or to re-use the access token in the security context of an `oauth2ResourceServer`.

Sample usage
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
This exposes two beans that we can auto-wire in `@Component` or `@Configuration`, for instance to generate `@HttpExchange` implementations as follows (mind the `expose-builder: true` for `bidule-client`):
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

## Unit & Integration Testing With Security

Testing access control requires configuring the test security context.  For that, `spring-security-test` provides `MockMvc` request post-processors and `WebTestClient` mutators, but this can work only in the context of a request, which limits its usage to controllers.

To test any type of `@Component` (`@Controller`, of course, but also `@Service` and `@Repository`) there are  only two options:
- build tests security context by yourself and populate it with stubbed / mocked authentications
- use annotations to do it for you (this is where [spring-addons-oauth2-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) jumps in)

Useful resources:
- [spring-addons-oauth2-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) contains test annotations and its README documents usage
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
