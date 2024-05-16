# Ease OAuth2 / OpenID Configuration & Tests in Spring Boot 3 

## Useful links
- [OAuth2 security configuration tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#securing-spring-applications-with-oauth2) (with and without `spring-addons-starter-oidc`)
- [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc) a Spring Boot starter pushing OAuth2 clients & resource server security auto-configuration to the next level
- [`spring-addons-oauth2-test`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) annotations for populating test security-context with OAuth2 authentication instances
- [`spring-addons-starter-oidc-test`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc-test) ease unit-tests in applications using `spring-addons-starter-oidc`
- [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest) experimental auto-configuration for `RestClient`, `WebClient` and `@HttpExchange` proxies (base-URL, Basic & OAuth2 Bearer auth)
- [Release Notes](https://github.com/ch4mpy/spring-addons/tree/master/release-notes.md)
- [Maven-Central Reminders](https://github.com/ch4mpy/spring-addons/tree/master/maven-central.md)

## Breaking News

In `7.7.0`, some `@ConfigurationProperties` were changed to inner-class definition (instead of standing in a source file of their own). Migration should be no more complicated than organizing imports.

The OAuth2 BFF tutorial is now [on Baeldung](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2). It was deeply refreshed in the process and now contains samples for Angular, React (Next.js) and Vue (Vite).

## [OIDC starter](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc)

With `spring-addons-starter-oidc`, you might need 0 Java conf, even in scenarios like:
- accepting tokens issued by several trussted authorization servers
- mapping authorities from a variety of claims
- needing custom OAuth2 redirection URI or HTTP status
- having per environment CORS configuration (not allowing the same origins in staging and prod for instance)
- exposing CSRF token as a cookie accessible to a single-page application
- logging out from an authorization server not strictly implementing RP-Initiated Logout (case of Auth0 and Amazon Cognito for instance)
- adding extra parameters to authorization or token requests (like the `audience` required by Auth0)

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
