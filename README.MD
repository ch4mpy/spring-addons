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

The content for [getting started with Keycloak](https://www.baeldung.com/spring-boot-keycloak) was moved to Baeldung. It is built without `spring-addons-starter-oidc`, but contains the very minimal to understand Spring Security configuration for OAuth2. Start there.

The [OAuth2 BFF tutorial](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2) is on Baeldung too. It contains samples for Angular, React (Next.js) and Vue (Vite).

`7.9.0-M3`, is out. It is designed to work with Spring Boot `3.4.0-M3`, Security `6.4.0-M4`, and Cloud `2024.0.0-M1`. It comes with two main features:
- Working [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) for OAuth2 clients with `oauth2Login` (at last :/). If you don't know about Back-Channel Logout, it is some sort of *"single sign-out"* for systems with *Single Sign On* (SSO). Keycloak is a sample of an OpenID Provider capable of emitting Back-Channel Logout to a Spring client (like a Gateway used as an OAuth2 BFF). It is disabled by default. The default internal logout URI and session cookie name can be overriden in properties:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          back-channel-logout:
            enabled: true
            internal-logout-uri: ${gateway-uri}/logout/connect/back-channel/quiz-bff
            cookie-name: JSESSION-ID
```
- The status for unauthorized requests can now be configured in properties for client with `oauth2Login`. Default is still `302 Found` (redirect to login), but it's now super easy to change it to `401 Unauthorized`, for instance on a Gateway facing single page or mobile applications:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          oauth2-redirections:
            authentication-entry-point: UNAUTHORIZED
```

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
