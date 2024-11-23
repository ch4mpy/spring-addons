# spring-addons 
Make Spring developers' life easier when OAuth2 / OpenID is involved

## Latest news

:rocket: `8.0.0`, is out. It is designed to work with Spring Boot `3.4.0` (Security `6.4.0` and Cloud `2024.0.0`). See [the release notes](https://github.com/ch4mpy/spring-addons/blob/master/release-notes.md#800) for details.

The new [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest) can be a game changer for inter-service calls when OAuth2 or an HTTP proxy is involved. Give it a try!

## [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc)

`spring-boot-starter-oauth2-client` and `spring-boot-starter-resource-server` defaults rarely satisfy a production use-case and we almost always need to write the `Security(Web)FilterChain` in application code, which can be a verbose, complicated, and error-prone task.

`spring-addons-starter-oidc` builds on top of _"offical"_ starters to significantly reduce the need for security configuration code. It even brings it down to 0 in most cases.

It's important to note that we have complete control over what `spring-addons-starter-oidc` auto-configures. The handles we have for that are application properties, of course, but also bean definitions: almost all auto-configured components are `@ConditionalOnMissingBean`, meaning that `spring-addons` backs off each time a component is explicitly defined in an application.

Auto-configuration for resource servers:
- accepting tokens issued by several trusted authorization servers
- mapping authorities from a variety of claims (including nested ones), with custom prefix and case
- CORS configuration
- allowing anonymous preflight requests using the path-matchers in CORS configuration

Auto-configuration for clients with `oauth2Login`:
- customizing OAuth2 responses:
  - specify the URI in `Location` header to activate a route after login / logout (defaults can be defined in application properties and overridden by the frontend using headers or query parameters)
  - set the HTTP status in the `2xx` range to observe the response in Javascript code and trigger plain navigation instead of letting the browser follow a redirection with a cross-origin request
- exposing CSRF token as a cookie accessible to a single-page application
- logging out from an authorization server not strictly implementing RP-Initiated Logout (case of Auth0 and Amazon Cognito for instance)
- activating and configuring Back-Channel Logout
- adding extra parameters to authorization & token requests (like the `audience` required by Auth0)
- CORS configuration
- allowing anonymous preflight requests using the path-matchers in CORS configuration

## [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest)

At the age of OpenAPI and client code generation, the main challenge for inter-service communication is the configuration of REST clients. Spring promotes the usage of `RestClient` or `WebClient`, but configuring those for `Basic` or `Bearer` authentication, an HTTP proxy, and connection & read timeouts is pretty complicated, verbose, and error-prone.

`spring-addons-starter-rest` makes this configuration a snap. It even exposes the clients or their builder as beans.

For OAuth2 authorization, we choose between using a new token provided by any Spring OAuth2 client `registration`, or re-use the access token in the security context of an `oauth2ResourceServer`.

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
This exposes pre-configured `RestClient` or `WebClient` beans (or their builders) that we can auto-wire in any kind of `@Component` - like `@Controller` & `@Service` - or use in `@Configuration` - for instance to generate implementations of `@HttpExchange` interfaces and expose them as beans.

Proxy configuration is applied by default to REST clients as soon as the `HTTP_PROXY` and `NO_PROXY` environment variables are set. This can be overridden and disabled with application properties.

## Unit & Integration Testing With Security

Testing access control requires configuring the test security context.  For that, `spring-security-test` provides `MockMvc` request post-processors and `WebTestClient` mutators, but this can work only in the context of a request, which limits its usage to controllers.

**To test any type of `@Component`** (`@Controller`, of course, but also `@Service` and `@Repository`) there are  only two options:
- build tests security context by ourself and populate it with stubbed / mocked authentications :cry:
- **use annotations** to do it for us (this is where [spring-addons-oauth2-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) jumps in) :smiley:

Also, **the test `Authentication` factories for resource servers in `spring-security-test` ignore more security conf than necessary**. For instance, when a JWT decoder is used:
1. the JWT Bearer string is decoded, validated, and turned into a `org.springframework.security.oauth2.jwt.Jwt` by a `JwtDecoder`
2. this `Jwt` (not JWT) is turned into something extending `AbstractAuthenticationToken` by an authentication converter. This step includes converting claims to authorities and the choice of a specific `Authentication` implementation.
3. the `Authentication` instance is put in the security context

It is common to mock the `JwtDecoder` in tests to avoid needing an actual authorization server. But an important difference between `spring-addons` and `spring-security-test` is:
- `@WithJwt` builds a stub `Jwt` (not JWT) from a JSON payload  in test resources and then delegates the `AuthenticationToken` creation to the configured authentication converter
- `jwt()` builds a `JwtAuthenticationToken`, using only the Java DSL and completely ignoring the authentication converter :sob:

So, for `@WithJwt` to work as expected, we should expose the authentication converter as a bean. Still, only it provides stuff like covering authorities conversion logic and using custom `Authentication` implementations in tests. Similar observations can be made for introspection. 

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
