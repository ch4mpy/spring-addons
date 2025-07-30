# Ease OAuth2 / OpenID in Spring RESTful backends

`8.1.20` is designed to work with Spring Boot `3.5.x` (Security `6.5.x` and Cloud `2025.0.x`).

`9.0.2-M1` is designed to work with Spring Boot `4.0.0-M1` (Security `7.0.x` and Cloud `2025.1.x`). Source is tracked on branch boot-4 until Boot `4.0.0` is released.

[`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest) is a game changer for inter-service calls when OAuth2, self-signed SSL certificates, or HTTP proxies are involved. Give it a try!

## Minimal OAuth2 Background for Spring Backends

This repo hosts [tutorials for configuring Spring RESTful backends with OAuth2 / OIDC](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#securing-spring-applications-with-oauth2). **Remember that a few weeks of trials and error can save 15 minutes in a README.** So, you'd better carefully read the [_OAuth2 essentials_](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#1-oauth2-essentials) section, as well as [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc#spring-addons-starter-oidc) and [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest#auto-configure-restclient-or-webclient-beans) READMEs before jumping into implementation.

Three tutorials from this repo have been moved to Baeldung:
- [Getting started with Keycloak & Spring Boot](https://www.baeldung.com/spring-boot-keycloak)
- [Creating an OAuth2 BFF with `spring-cloud-gateway` and consuming it with Single-Page Applications](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2)
- [Testing access control with mocked OAuth2 authentications](https://www.baeldung.com/spring-oauth-testing-access-control)

## [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc)

When using just `spring-boot-starter-oauth2-client` or `spring-boot-starter-resource-server` we almost always end up writing the `Security(Web)FilterChain` ourselves, which requires a solid security background, some knowledge of Spring Security internals, and can be verbose.

`spring-addons-starter-oidc` builds on top of _"offical"_ starters to significantly reduce the need for security configuration code. It even brings it down to 0 in most cases.

**We have complete control over what `spring-addons-starter-oidc` auto-configures.** With application properties, of course, but also bean definitions: almost all auto-configured components are `@ConditionalOnMissingBean`, meaning that `spring-addons` backs off each time a component is explicitly defined in an application. But no need to define a complete security filter-chain, defining just the component to override should be enough.

Auto-configuration for resource servers:
- accepting tokens issued by several trusted authorization servers
- mapping authorities from a variety of claims (including nested ones), with custom prefix and case
- CORS configuration
- allowing anonymous preflight requests using the path-matchers in CORS configuration

Auto-configuration for clients with `oauth2Login`:
- customizing responses returned to the frontend during the authorization-code and RP-Initiated Logout flows:
  - specify the URI in `Location` header to activate a route after login / logout (defaults can be defined in application properties and overridden by the frontend using headers or query parameters)
  - avoid some CORS issues with the authorization server: set the HTTP status in the `2xx` range to observe the response and handle the redirection in Javascript code instead of letting the browser follow with an Ajax request. There is no reason for these redirections to be cross-origin requests, plain navigation is what should actually happen.
- exposing CSRF token as a cookie accessible to a single-page application
- logging out from an authorization server not strictly implementing RP-Initiated Logout (case of Auth0 and Amazon Cognito for instance)
- activating and configuring Back-Channel Logout
- adding extra parameters to authorization & token requests (like the `audience` required by Auth0)
- CORS configuration
- allowing anonymous preflight requests using the path-matchers in CORS configuration

## [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest)

At an age where OpenAPI specs can be generated from REST APIs source code, and the client code to consume these APIs generated from the specs, the main challenge for inter-service communication is the configuration of REST clients. 

Spring promotes the usage of `RestClient` or `WebClient`, but configuration for the following can be pretty complicated, verbose, and error-prone:
- `Basic` or `Bearer` authentication
- going through an HTTP proxy
- connection & read timeouts
- trusting SSL certificates configured in an SSL bundle
- disabling SSL certificates validation
- switching the underlying HTTP client library from JDK's one to `http-components` or `jetty`

`spring-addons-starter-rest` makes this configuration a snap.

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
                # Configure RestClient / WebClient to trust a certificate described with an SSL bundle (should point to an entry in spring.ssl.bundle properties)
                ssl-bundle: client
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
This exposes pre-configured `RestClient` or `WebClient` beans (or their builders) that we can auto-wire in any kind of `@Component` - like `@Controller` & `@Service` - or use in `@Configuration` - for instance to generate implementations of `@HttpExchange` interfaces and expose them as beans.

Proxy configuration is applied by default to REST clients as soon as the `HTTP_PROXY` and `NO_PROXY` environment variables are set. This can be overridden and disabled with application properties.

## Unit & Integration Testing With Security

Testing access control requires configuring the test security context with a fine-tuned `Authentication` instance.

For that, `spring-security-test`  provides `MockMvc` request post-processors and `WebTestClient` mutators, but it can work only in the context of a request, which limits its usage to controllers. **To test any type of `@Component`** (`@Controller`, of course, but also `@Service` and `@Repository`) there are  only two options:
- build tests security context by ourself and populate it with stubbed / mocked authentications :cry:
- **use annotations** to do it for us (this is where [spring-addons-oauth2-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) jumps in) :smiley:

Also, a notable difference between `@MockJwt` and those in `spring-security-test` is that **`spring-security-test` ignores the authentication converter defined in the security conf :sob:**. To understand the consequences, let's consider the flow to build the security context in a resource server with a JWT decoder:
1. the JWT Bearer string is decoded, validated, and turned into a `org.springframework.security.oauth2.jwt.Jwt` by a `JwtDecoder`
2. this `Jwt` (not JWT) is turned into something extending `AbstractAuthenticationToken` by an authentication converter. This step includes converting claims to authorities and the choice of a specific `Authentication` implementation.
3. the `Authentication` instance is put in the security context

With `@WithJwt`, only the 1st step is mocked. A stub `Jwt` (not JWT) is built using a JSON payload in test resources and provided to the authentication converter. With `spring-security-test` post-processors and mutators, factories skip to step 3 and build a stub `Authentication` themselves, setting properties with what is provided in the test code. So, authorities conversion logic is used only with `@WithJwt`. Similarly, a custom `Authentication` implementation will be used in tests only if the authentication converter is called by the factory, and as so, with `@WithJwt`, but not with `.jwt()` post-processor.

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
