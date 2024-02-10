# Ease OAuth2 / OpenID Configuration & Tests in Spring Boot 3 

Repository for:
- [`spring-addons-oauth2-test`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) annotations for populating test security-context with OAuth2 authentication instances
- [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc) a Spring Boot starter to further ease configuration in Spring OAuth2 clients and OAuth2 resource servers
- [`spring-addons-starter-oidc-test`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc-test) ease unit-tests in applications using `spring-addons-starter-oidc`
- quite a few [OAuth2 tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#securing-spring-applications-with-oauth2) (with and without `spring-addons-starter-oidc`)

Jump to:
- [1. Breaking news](#news)
- [2. Spring Boot OIDC Starter](#oidc-starter)
- [3. Unit & Integration Testing With Security](#unit-tests)
- [4. Where to Start](#start)
- [Release Notes](https://github.com/ch4mpy/spring-addons/tree/master/release-notes.md)
- [Maven-Central Reminders](https://github.com/ch4mpy/spring-addons/tree/master/maven-central.md)

## 1. <a name="news"/>Breaking News
Main README was split into specialized ones and the part about [`spring-addons-starter-oidc`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc) features and customization considerably enriched.

You can **test your OAuth2 / OpenID knowledge with a dedicated quiz** available at [https://quiz.c4-soft.com/ui/quizzes](https://quiz.c4-soft.com/ui/quizzes) before you rush into configuring your applications.

**Important warning for those using `@WithJwt` (and since `7.3.0`, `@WithMockJwtAuth`) but not `spring-addons-starter-oidc`**: you should expose your JWT converter as a bean. In practice, instead of inlining the authentication converter in the `SecurityFilterChain` definition, use something like:
```java
@Bean
// It is important that what implements Converter<Jwt, AbstractAuthenticationToken> is exposed as a @Bean
JwtAuthenticationConverter authenticationConverter() {
    final var authenticationConverter = new JwtAuthenticationConverter();
    authenticationConverter.setPrincipalClaimName(StandardClaimNames.PREFERRED_USERNAME);
    authenticationConverter
            .setJwtGrantedAuthoritiesConverter(
                    (jwt) -> Optional
                            .ofNullable(jwt.getClaimAsStringList("roles"))
                            .orElse(List.of())
                            .stream()
                            .map(SimpleGrantedAuthority::new)
                            .map(GrantedAuthority.class::cast)
                            .toList());
    return authenticationConverter;
}

@Bean
// This bean can then be injected in your SecurityFilterChain as follow
SecurityFilterChain securityFilterCHain(HttpSecurity http, Converter<Jwt, AbstractAuthenticationToken> authenticationConverter) throws Exception {
    http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(authenticationConverter)));
    ...
    return http.build();
}
```
This is important for the test annotation to get this authentication converter from the test context (and use it to build the `Authentication` instance it puts in the test security context).

## 2. <a name="oidc-starter"/>spring-addons-starter-oidc

**This starter is designed to push auto-configuration to the next level** and does nothing more than helping you to configure Spring Security beans using application properties.

**In most cases, you'll need 0 Java conf**, even in scenarios like:
- accepting tokens issued by several trussted authorization servers
- mapping authorities from a variety of claims
- needing custom OAuth2 redirection URI or HTTP status
- having per environment CORS configuration (not allowing the same origins in staging and prod for instance)
- exposing CSRF token as a cookie accessible to a single-page application
- logging out from an authorization server not strictly implementing RP-Initiated Logout (case of Auth0 and Amazon Cognito for instance)
- adding extra parameters to authorization or token requests (like the `audience` required by Auth0)

[The module README](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc) exposes features, auto-configuration options and default beans overriding.

An effort was made to make [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials), Javadoc as informative as possible. You should get useful code snippets there.

## 3. <a name="unit-tests"/>Unit & Integration Testing With Security

Testing method security (`@PreAuthorize`, `@PostFilter`, etc.) requires to configure the security context. `Spring-security-test` provides with `MockMvc` request post-processors and `WebTestClient` mutators to do so, but this requires the context of a request, which limits its usage to testing secured controllers.

To test method security on any type of `@Component` (`@Controller`, off course, but also `@Service` and `@Repository`) there are  only two options: build tests security context by yourself and populate it with stubbed / mocked authentications, or use annotations to do it for you. **This lib contains annotations to configure test security context with OAuth2 authentication at your hand.**

An [article covering the usage of OAuth2 test annotations from this lib](https://www.baeldung.com/spring-oauth-testing-access-control) was published on Baeldung. This, along with all [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) and [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) source-code (which contain a lot of unit and integration testing), should be enough to get you started.

You should also directly refer to the READMEs of:
- [spring-addons-oauth2-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) if you do not use `spring-addons-starter-oidc`
- [spring-addons-starter-oidc-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc-test) if you do use `spring-addons-starter-oidc`

## 4. <a name="start"/>Where to Start

[Tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) which cover:
- just enough OAuth2 theory
- dev environment configuration (SSL certificate, Keycloak)
- various resource-servers security configuration scenarios
- security rules unit-testing

[Samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) cover:
- `@Controller`, `@Service` and `@Repository` **unit testing**
- **integration testing** (`@SpringBootTest`) with mocked authentication
- all combinations with choices from the following 3 points:
  * webmvc / webflux
  * JWT decoder / access token introspection
  * `OAuthentication<OpenidClaimSet>` / Spring default `Authentication` implementation (`JwtAuthenticationToken` for JWT decoder or `BearerTokenAuthentication` for token introspection)
  
Modules READMEs:
- [spring-addons-oauth2-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) or [Baeldung article](https://www.baeldung.com/spring-oauth-testing-access-control) for testing access control in applications configured without `spring-addons-starter-oidc`
- [spring-addons-starter-oidc](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc) for features, configuration options and default beans overrides
- [spring-addons-starter-oidc-test](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc-test) for testing applications configured using `spring-addons-starter-oidc`
