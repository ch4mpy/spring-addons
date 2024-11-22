# Ease OAuth2 / OpenID Configuration & Tests in Spring Boot 3 

## What's new in `8.0.0`

`8.0.0`, is out. It is designed to work with Spring Boot `3.4.0` (Security `6.4.0` and Cloud `2024.0.0`).

- [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest) now expose as `@Bean` some `RestClient` and `WebClient` instances (or builders) with the following configured using application properties:
  - Base URI
  - `Basic` or `Bearer` authorization. For the second, with a choice of using an OAuth2 client registration or forwarding the access token in the security context.
  - Connection & read timeouts
  - HTTP or SOCKS proxy, with consideration of the standard `HTTP_PROXY` and `NO_PROXY` environment variables (finer-grained configuration can be applied with custom properties)
- [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc) auto-configuration for `oauth2Login` is improved with:
  - Working [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html), even with cookie-based CSRF protection and `logout+jwt` tokens (which makes it finally usable with [OAuth2 BFF](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2) & [Keycloak](https://www.baeldung.com/spring-boot-keycloak)).
  - Configurable status for unauthorized requests. The default is still `302 Found` (redirect to login), but it's a snap to change it to `401 Unauthorized` (like REST APIs should return, even stateful ones).
- `OAuthentication` now extends `AbstractOAuth2TokenAuthenticationToken` for a better integration with the rest of the Spring Security ecosystem. See the [migration guide](https://github.com/ch4mpy/spring-addons/tree/master/migrate-to-8.0.0.md) for details.

## [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc)

A spring Boot starter to reduce Java Security conf to 0 in scenarios like:
- accepting tokens issued by several trusted authorization servers
- mapping authorities from a variety of claims (including nested ones), with custom prefix and case
- customizing OAuth2 responses:
  - URI to activate a route after login / logout (defaults can be defined in application properties and overridden by the frontend using headers or query parameters)
  - HTTP status to observe and trigger a plain navigation in Javascript code instead of letting the browser follow a redirection with a cross-origin request
- exposing CSRF token as a cookie accessible to a single-page application
- logging out from an authorization server not strictly implementing RP-Initiated Logout (case of Auth0 and Amazon Cognito for instance)
- activating and configuring Back-Channel Logout in a Spring application with `oauth2Login`
- adding extra parameters to authorization & token requests (like the `audience` required by Auth0)
- having per environment CORS configuration (not allowing the same origins in staging and prod for instance)
- allowing anonymous preflight requests using the path-matchers in CORS configuration

## [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest)

A spring Boot starter to expose REST clients auto-configured with requests authorization, HTTP proxy settings, and more. For OAuth2 authorization, we have a choice of using a new token using any Spring OAuth2 client `registration`, or to re-use the access token in the security context of an `oauth2ResourceServer`.

Sample usage
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          # Exposes a RestClient bean named machinClient (or WebClient in a WebFlux app)
          machin-client:
            base-url: ${machin-api}
            authorization:
              oauth2:
                # Authorize outgoing requests with the Bearer token in the security context (possible only in a resource server app)
                forward-bearer: true
          # Exposes a RestClient.Builder bean named biduleClientBuilder (mind the "expose-builder: true")
          bidule-client:
            base-url: ${bidule-api}
            # Expose the builder instead of an already built client (to fine tune its conf)
            expose-builder: true
            authorization:
              oauth2:
                # Authorize outgoing requests with the Bearer token obtained using an OAuth2 client registration
                oauth2-registration-id: bidule-registration
```
This exposes pre-configured beans that we can auto-wire in any kind of `@Component`, like `@Controller` or `@Service`, or use in `@Configuration`. For instance:
```java
@Configuration
public class RestConfiguration {
  /** 
   * @param machinClient pre-configured by spring-addons-starter-rest using application properties
   * @return a generated implementation of the {@link MachinApi} {@link HttpExchange &#64;HttpExchange}, exposed as a bean named "machinApi".
   */
  @Bean
  MachinApi machinApi(RestClient machinClient) throws Exception {
    return new RestClientHttpExchangeProxyFactoryBean<>(MachinApi.class, machinClient).getObject();
  }

  /** 
   * @param biduleClientBuilder pre-configured using application properties
   * @return a {@link RestClient} bean named "biduleClient"
   */
  @Bean
  RestClient biduleClient(RestClient.Builder biduleClientBuilder) throws Exception {
    // Fine-tune biduleClientBuilder configuration
    return biduleClientBuilder.build();
  }

  /** 
   * @param biduleClient the bean exposed just above
   * @return a generated implementation of the {@link BiduleApi} {@link HttpExchange &#64;HttpExchange}, exposed as a bean named "biduleApi".
   */
  @Bean
  BiduleApi biduleApi(RestClient biduleClient) throws Exception {
    return new RestClientHttpExchangeProxyFactoryBean<>(BiduleApi.class, biduleClient).getObject();
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
