You can now **test your OAuth2 / OpenID knowledge with a dedicated quiz** available at [https://quiz.c4-soft.com/ui/quizzes](https://quiz.c4-soft.com/ui/quizzes) before you rush into configuring your applications. 

Please follow the [migration guide](https://github.com/ch4mpy/spring-addons/blob/master/7.0.0-migration-guide.md) to move from `6.x` to `7.x`.

All samples and tutorials sources are migrated to latest starter and test annotations, but some READMEs might still need a refresh. Please make sure you refer to source code for up-to-date configuration.

**Important warning**: when using `@WithJwt` (and since `7.3.0`, `@WithMockJwtAuth`), you should expose your JWT converter as a bean. In practice, instead of inlining the authentication converter in the `SecurityFilterChain` definition, use something like:
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
SecurityFilterChain securityFilterCHain(HttpSecurity http, Converter<Jwt, AbstractAuthenticationToken> authenticationConverter) throws Exception {
    http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(authenticationConverter)));
    
    return http.build();
}
```
This is important for the test annotation to get this authentication converter from the test context (and use it to build the `Authentication` instance it puts in the test security context). Of course `spring-addons-starter-oidc` does this already, so if you're using the default authentication converter, there is nothing to do (and if you're not, then you probably already exposed such a bean to override spring-addons one).

# Ease OpenID Configuration & Tests in Spring Boot 3 
The libraries hosted in this repo shine in two domains:
- providing with annotations to mock OAuth2 `Authentication` for JUnit `@Test` and `@ParameterizedTest`:
  * `@WithMockAuthentication` with `@AuthenticationSource` and `@ParameterizedAuthentication`
  * `@WithJwt` which uses the JWT authentication converter defined in security configuration to build the right type of `Authentication` (with the right authorities and name) based on a JSON file on he classpath (or plain Java String
  * `@WithOpaqueToken` same as `@WithJwt` for introspection, using the `OpaqueTokenAuthenticationConverter` in the security configuration
  * more specialized annotations for specific authentication implementations (`@WithOAuth2Login`, `@WithOidcLogin`, etc.) or to use as elements for your own test annotations in applications using custom OAuth2 `Authentication` implementations
- pushing OIDC auto-configuration to the next level in Spring Boot 3 applications. As shown in **[Tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials)**, with 0 Java conf (just properties), we can configure:
  * authorities mapping (source claims, prefix and case transformation), without having to provide authentication converter, user service or `GrantedAuthoritiesMapper` in each app
  * fine-grained CORS configuration (per path matcher), which enables to override allowed origins as environment variable when switching from `localhost` to `dev` or `prod` environments
  * sessions & CSRF disabled by default on resource server and enabled on clients. If a cookie repo is chosen for CSRF (as required by Angular, React, Vue, etc.), then the right request handler is configured and a filter to actually set the cookie is added
  * basic access control: `permitAll` for a list of path matchers and `authenticated` as default (to be fine-tuned with method security or a configuration post-processor bean)
  * for clients only:
    - logout success handler for OPs not strictly following the standard (exotic parameter names or missing `end_session_endpoint` in OpenID configuration). Auth0 and Amazon Cognito are samples of such OPs.
    - client host and port explicitly provided in login configuration to avoid [redirection issues when the client does not use 8080 (or 8443 if SSL is enabled)](https://github.com/spring-projects/spring-security/issues/12307)
    - add custom params to authorization-code request (like the `audience` required by Auth0). These parameters are defined in application properties for each client registration.
    - multi-tenancy: allow users to be logged in with more than one OpenID Provider and keep track of their different `Authentication` instances (one per OP, with most probably different `subject` and username).

Jump to:
- [0. Risks Of Using These Libs And Mitigations](#drawbacks)
- [1. Spring Boot OIDC Starter](#oidc-starter)
- [2. Unit & Integration Testing With Security](#unit-tests)
- [3. Where to Start](#start)
- [4. Versions & Requirements](#versions)
- [5. Release Notes](#release-notes)
- [6. Maven-Central Reminders](#maven-central)

## 0. <a name="drawbacks"/>Risks Of Using These Libs And Mitigations
Neither the owner of this repo nor any of the contributors are part of Spring Security team. At best, some are occasional contributors to the "official" framework.

However, unless you have a deep knowledge of Spring Security for OAuth2, using `spring-addons-starter-oidc` might actually be safer than experimenting with the conf by yourself. And the more popularity this repo gets, the safer it is: more people detect potential issues, more people can keep it alive if its initiator disappears and, if some features where to become popular enough, Spring team could consider pulling it in the official framework.

Also, all you have to do to opt-out `spring-addons-starter-oidc` at any point in time is writing Spring Security Configuration by yourself. Refer to tutorials if you need some guidance to do that, the following are written without `spring-addons-starter-oidc` (just `spring-boot-starter-oauth2-client` or `spring-boot-starter-oauth2-resource-server`):
- [reactive-client](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/reactive-client)
- [reactive-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/reactive-resource-server)
- [servlet-client](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-client)
- [servlet-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-resource-server)

What are the identified risks of using the resources from such a repo and how can you protect against it?
- *what if the updates to latest dependencies stop and no PR are merged anymore?* You can fork this repo and start a new branch from the last tag you like
- *what if the library takes a direction I don't like?* Same as for a stale repo
- *what if the owner deletes this repo or makes it private?* The source code for each release is published to maven-central. You can get the source [there](https://repo1.maven.org/maven2/com/c4-soft/springaddons/) or from any of the forks on GitHub (about 50 in August 2023).
- *what is the risk of vulnerabilities introduced by the code in these libs?* This depends on the lib:
  * libs to be used during tests (`spring-addons-oauth2-test` and `spring-addons-starter-oidc-test`) should be imported with `test` scope => it should not be present at runtime => no risk in production
  * `spring-addons-starter-oidc` does some auto-configuration for you: it defines Spring beans involved in your application security. So yes, if a default is miss-configured in this lib, it can have an impact on your app. You should however consider that:
    - an increasing number of user inspect it and open issues or PRs when detecting a problem (the community is probably much bigger than your team working at detecting Spring Security configuration issues in your own projects)
    - having code centralised at one place and reused at many places reduces the risk of a careless mistake in one of your app

## 1. <a name="oidc-starter"/>Spring Boot Starter
**This starter is designed to push auto-configuration to the next level** and does nothing more than helping you to configure Spring Security beans using application properties.

`spring-addons-oidc-starter` does not replace `spring-boot-starter-oauth2-resource-server` and `spring-boot-starter-oauth2-client`, it uses application properties to configure a few beans designed to be picked by Spring Boot official "starters". The aim is to reduce Java code and ease application deployment across environments. In most cases, you should need 0 Java conf. An effort was made to make [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials), Javadoc as informative as possible. Please refer there for more details.

If you are curious enough, you might inspect what is auto-configured (and under which conditions) by reading the source code, starting from the [org.springframework.boot.autoconfigure.AutoConfiguration.imports](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-starter-oidc/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports) file, which is the Spring Boot standard entry-point defining what is loaded when a jar is on the classpath.

You can refer to [module, dependency, class and other diagrams](https://sourcespy.com/github/ch4mpyspringaddons/) for a general overview of the repository.

### 1.1. Usage
**If you are not absolutely sure why you need an OAuth2 client (with `oauth2Login` in Spring, but secured with sessions, not access tokens) or an OAuth2 resource server configuration (secured with access tokens, not sessions, but without `oauth2Login`), please read the [OAuth2 essentials section](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#1-oauth2-essentials) of the tutorials.** This might save you a lot of time and effort.

Add `com.c4-soft.springaddons:spring-addons-starter-oidc` to your dependencies, in addition to `org.springframework.boot:spring-boot-starter-oauth2-client` or `org.springframework.boot:spring-boot-starter-oauth2-resource-server`.

If configuring an OAuth2 client (with `oauth2Login`), define the standard Spring Boot `provider` and `registration` properties for OAuth2 clients.

If configuring an OAuth2 resource server with access token introspection, define the standard Spring Boot `opaquetoken` properties.

Then, define the relevant `com.c4-soft.springaddons.oidc` properties for your use case. There are many complete [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) and [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) you should refer to, but here are a few demos for different use-cases and OpenID Providers:

#### 1.1.1. Resource Server with JWT decoder
For a REST API secured with JWT access tokens, you need:
```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<!-- For a reactive application, use spring-boot-starter-webflux instead -->
	<artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>

<dependency>
	<groupId>com.c4-soft.springaddons</groupId>
	<artifactId>spring-addons-starter-oidc</artifactId>
</dependency>
```
And
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: https://oidc.c4-soft.com/auth/realms/master
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        resourceserver:
          permit-all:
          - "/greet/public"
          cors:
          - path: /**
            allowed-origin-patterns: http://localhost:4200
```
Above configuration will create an application without sessions nor CSRF protection, and 401 will be answered to unauthorized requests to protected resources.

#### 1.1.2. Client
For an app serving Thymeleaf templates with login and logout:
```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<!-- For a reactive application, use spring-boot-starter-webflux instead -->
	<artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>

<dependency>
	<groupId>com.c4-soft.springaddons</groupId>
	<artifactId>spring-addons-starter-oidc</artifactId>
</dependency>
```
And
```yaml
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-client-id: change-me
cognito-secret: change-me

spring:
  security:
    oauth2:
      client:
        provider:
          cognito:
            issuer-uri: ${cognito-issuer}
        registration:
          cognito-authorization-code:
            authorization-grant-type: authorization_code
            client-id: ${cognito-client-id}
            client-secret: ${cognito-secret}
            provider: cognito
            scope: openid,profile,email,offline_access
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${cognito-issuer}
          username-claim: username
          authorities:
          - path: cognito:groups
        client:
          security-matchers:
          - /**
          permit-all:
          - /login/**
          - /oauth2/**
          - /
          # Auth0 and Cognito do not follow strictly the OpenID RP-Initiated Logout spec and need specific configuration
          oauth2-logout:
            cognito-authorization-code:
              uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: logout_uri
```
Above configuration will create an application secured with sessions (not access tokens), with CSRF protection enabled, and unauthorized requests to protected resources will be redirected to login.

#### 1.1.3. Client and Resource Server
For an app exposing publicly both
- Thymeleaf templates secured with session (with login and logout), all templates being served with `/ui` prefix (but index which is at `/`)
- a REST API secured with access token
```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<!-- In a reactive application, use only spring-boot-starter-webflux -->
	<artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<!-- Used for WebClient to call the REST API from controllers serving Thymeleaf templates -->
	<artifactId>spring-boot-starter-webflux</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>

<dependency>
	<groupId>com.c4-soft.springaddons</groupId>
	<artifactId>spring-addons-starter-oidc</artifactId>
</dependency>
```
And
```yaml
auth0-issuer: https://oidc.c4-soft.com/auth/realms/master
auth0-client-id: change-me
auth0-secret: change-me

spring:
  security:
    oauth2:
      client:
        provider:
          auth0:
            issuer-uri: ${auth0-issuer}
        registration:
          auth0-authorization-code:
            authorization-grant-type: authorization_code
            client-id: ${auth0-client-id}
            client-secret: ${auth0-secret}
            provider: auth0
            scope: openid,profile,email,offline_access
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: $['https://c4-soft.com/user']['roles']
          - path: $.permissions
        client:
          security-matchers:
          - /login/**
          - /oauth2/**
          - /logout
          - /
          - /ui/**
          permit-all:
          - /login/**
          - /oauth2/**
          - /
          # Auth0 and Cognito do not follow strictly the OpenID RP-Initiated Logout spec and need specific configuration
          oauth2-logout:
            auth0-authorization-code:
              uri: ${auth0-issuer}v2/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: returnTo
          # Auth0 requires an "audience" parameter in authorization-code request to deliver JWTs
          authorization-request-params:
            auth0-authorization-code:
            - name: audience
              value: demo.c4-soft.com
        resourceserver:
          permit-all:
          - "/greet/public"
```
With the above configuration, two distinct security filter-chains will be defined:
- a client one with sessions (and CSRF protection enabled), intercepting all requests to UI templates as well as those involved in login and logout, and redirecting to login unauthorized requests to protected templates.
- a resource server one acting as default (with lowest precedence to process all requests that were not matched with client filter-chain `securityMatchers`), without sessions (requests are secured with JWT access tokens) nor CSRF protections, and returning 401 to unauthorized requests to protected resources.

### 1.2. Customizing Auto-Configuration
First use your IDE auto-completion to check if there isn't an existing application property covering your needs: a lot is configurable from properties, and all properties are documented.

You can override about any `@Bean` defined by spring-addons (almost all are `@ConditionalOnMissingBean`). Here are a few handy ones:
- `(Reactive)JwtAbstractAuthenticationTokenConverter`: take control on the `Authentication` instance built after a JWT was successfully decoded and validated
- `(Reactive)OpaqueTokenAuthenticationConverter`: take control on the `Authentication` instance built after an access token was successfully introspected
- `ClaimSetAuthoritiesConverter`: opt-out the `ConfigurableClaimSetAuthoritiesConverter`, responsible for authorities mapping
- `GrantedAuthoritiesMapper`: in OAuth2 clients, opt-out the default `GrantedAuthoritiesMapper` (which delegates authorities mapping to the `ConfigurableClaimSetAuthoritiesConverter` just above)
- `(Reactive)AuthenticationManagerResolver`: opt-out the authentication manager implementing static multi-tenancy for resource servers with JWT decoders
- `ResourceServerAuthorizeExchangeSpecPostProcessor`, `ClientAuthorizeExchangeSpecPostProcessor`, `ClientAuthorizeExchangeSpecPostProcessor` or `ResourceServerAuthorizeExchangeSpecPostProcessor`: fine-grained access control from configuration (an alternative is using `@Enable(Reactive)MethodSecurity` and `@PreAuthorize` on controller methods)
- `ResourceServerHttpSecurityPostProcessor` or `ClientHttpSecurityPostProcessor`: post-process spring-addons auto-configured `SecurityFilterChains` (this enables to change absolutely anything from it).

### 1.3. Disabling `spring-addons-oidc-starter`
The easiest way is to exclude it from the classpath, but you may also turn the auto-configuration off by:
- setting `com.c4-soft.springaddons.oidc.resourceserver.enabled` to `false` (this disables the resource server `SecurityFilterChain` bean instantiation, as well as all of its default dependencies)
- leaving `com.c4-soft.springaddons.oidc.client.securityMatcher` empty (this disables the client `SecurityFilterChain` bean instantiation, as well as all of its default dependencies)

## 2. <a name="unit-tests"/>Unit & Integration Testing With Security
Testing method security (`@PreAuthorize`, `@PostFilter`, etc.) requires to configure the security context. `Spring-security-test` provides with `MockMvc` request post-processors and `WebTestClient` mutators to do so, but this requires the context of a request, which limits its usage to testing secured controllers.

To test method security on any type of `@Component` (`@Controller`, off course, but also `@Service` and `@Repository`) there are  only two options: build tests security context by yourself and populate it with stubbed / mocked authentications, or use annotations to do it for you. **This lib contains annotations to configure test security context with OAuth2 authentication at your hand.**

An [article covering the usage of OAuth2 test annotations from this lib](https://www.baeldung.com/spring-oauth-testing-access-control) was published on Baeldung. This, along with all [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) and [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) source-code (which contain a lot of unit and integration testing), should be enough to get you started.

However, since this article was published, test annotations have improved.

### 2.1. Sample
Let's consider the following secured `@Service`
```java
@Service
public class SecuredService {
    @PreAuthorize("hasAuthority('NICE')")
    String nice() {
        return "Dear %s, glad to see you!".formatted(SecurityContextHolder.getContext().getAuthentication().getName());
    }
    
    @PreAuthorize("isAuthenticated()")
    String hello() {
        return "Hello %s.".formatted(SecurityContextHolder.getContext().getAuthentication().getName());
    }
}
```
Now, let's assume that you have a staging environment with a few representative users ("personas" if you are familiar with UX), for which you can get sample access tokens, and dump the claims in JSON files in test resources in (by decoding JWTs with a tool like https://jwt.io or introspecting opaque tokens). In the following, we'll consider you have a user named `brice` with `NICE` authority and another one named `igor` without the `NICE` authority. We'll also consider you have dumped sample claim-sets in `brice.json` and `igor.json`.

#### 2.1.1. Using `@WithMockAuthentication`
When testing RBAC (role-based access control), defining just authorities is frequently enough. Sometimes, defining the `Authentication#name` is necessary and in a few cases, application code needs a specific `Authentication` implementation. `@WithMockAuthentication` was designed to meet these requirements:
```java
@SpringBootTest(classes = { SecurityConfig.class, MessageService.class })
class MessageServiceTests {

	@Autowired
	private SecuredService securedService;
	
	@Test
	@WithMockAuthentication("BAD_BOY")
	void givenUserIsNotGrantedWithNice_whenCallNice_thenThrows() {
		assertThrows(Exception.class, () -> securedService.nice());
	}

	@Test
	@WithMockAuthentication(name = "brice", authorities = "NICE")
	void givenUserIsNice_whenCallNice_thenReturnsGreeting() {
		assertThat(securedService.nice()).isEqualTo("Dear brice, glad to see you!");
	}

	@ParameterizedTest
	@AuthenticationSource(
	    @WithMockAuthentication(name = "brice", authorities = "NICE"),
	    @WithMockAuthentication(name = "ch4mp", authorities = { "VERY_NICE", "AUTHOR" }))
	void givenUserIsAuthenticated_whenCallHello_thenReturnsGreeting(@ParameterizedAuthentication Authentication auth) {
		assertThat(securedService.hello()).isEqualTo("Hello %s.".formatted(auth.getName()));
	}
}
```

#### 2.1.1. Using `@WithJwt` or `@WithOpaqueToken` with JSON claim-sets
`@WithJwt` and `@WithOpaqueToken` enable to load those claim-sets and turn it into `Authentication` instances.

For the Authentication to be built as at runtime (type, authorities, name, claims, etc.), `@WithJwt` uses your `Converter<Jwt, ? extends AbstractAuthenticationToken>` and `@WithOpaqueToken` the `OpaqueTokenAuthenticationConverter` (or the reactive counterparts in reactive apps).

For the wiring to happen correctly, you need to import `AuthenticationFactoriesTestConf` (it is already imported when using one of `@AddonsWebmvcComponentTest`, `AutoConfigureAddonsWebmvcClientSecurity`, `AutoConfigureAddonsWebmvcResourceServerSecurity` or their reactive counterparts).
```java
@Import(AuthenticationFactoriesTestConf.class) // when using spring-addons-oauth2-test but not spring-addons-starter-oidc
// @AddonsWebmvcComponentTest // when using spring-addons-starter-oidc along with spring-addons-starter-oidc-test (already imports AuthenticationFactoriesTestConf for you)
@SpringBootTest(classes = { SecurityConfig.class, MessageService.class })
class MessageServiceTests {

	@Autowired
	private SecuredService securedService;

	@Autowired
	WithJwt.AuthenticationFactory authFactory;
	
	@Test
	@WithJwt("igor.json")
	void givenUserIsIgor_whenCallNice_thenThrows() {
		assertThrows(Exception.class, () -> securedService.nice());
	}

	@Test
	@WithJwt("brice.json")
	void givenUserIsBrice_whenCallNice_thenReturnsGreeting() {
		assertThat(securedService.nice()).isEqualTo("Dear brice, glad to see you!");
	}

	@ParameterizedTest
	@MethodSource("identities")
	void givenUserIsAuthenticated_whenCallHello_thenReturnsGreeting(@ParameterizedAuthentication Authentication auth) {
		assertThat(securedService.hello()).isEqualTo("Hello %s.".formatted(auth.getName()));
	}

	Stream<AbstractAuthenticationToken> identities() {
		return authFactory.authenticationsFrom("brice.json", "igor.json");
	}
}
```
There are we few things worth noting above:
- we are testing a `@Service` having methods decorated with `@PreAuthorize`, without `MockMvc` or `WebTestClient` (and their request post-processors or mutators)
- authorities and username will be coherent with claims during tests (it is not necessarily the case when we declare the 3 separately as done with MockMvc request post-processors and WebTestClient mutators). `WithJwt.AuthenticationFactory` uses the JWT authorities converter found in security configuration. As a consequence, `username` and `authorities` are resolved from claims, just as it is at runtime.
- the claims are loaded from a JSON files in the test classpath
- we are using JUnit 5 `@ParameterizedTest`: the test will run once for each of the authentication in the stream provided  by the `identities` method
- annotations fit so well with BDD (given-when-then): the test pre-conditions (given) are decorating the test instead of cluttering its content like MockMvc request post-processors and WebTestClient mutators do
- annotations can be very brief and expressive

**Important warning**: when using `@WithJwt` (and since `7.3.0`, `@WithMockJwtAuth`), you should expose your JWT converter as a bean. In practice, instead of inlining the authentication converter in the `SecurityFilterChain` definition, use something like:
```java
@Bean
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
SecurityFilterChain securityFilterCHain(HttpSecurity http, Converter<Jwt, AbstractAuthenticationToken> authenticationConverter) throws Exception {
    http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(authenticationConverter)));
    
    return http.build();
}
```

### 2.2. Which Dependency / Annotation to Use
`spring-addons-oauth2-test` is enough to use test annotations, but if you opted for `spring-addons-starter-oidc`, then `spring-addons-starter-oidc-test` is better suited as it comes with tooling to load spring-addons auto-configuration during tests (refer to the many samples for usage).

`@WithMockAuthentication` should be enough to test applications with RBAC (role-based access control): it allows to easily define `name` and `authorities`, as well as the Authentication a principal types to mock if your application code expects something specific.

In case your access-control uses more than just name and authorities, you'll probably need to define claim-set details. In this case, `@WithJwt` and `@WithOpaqueToken` can come pretty handy as it uses respectively the JWT or OpaqueToken authentication converter in your security configuration to build the authentication instance, using a JSON payload from the classpath (or a plain Java String): you might just dump payloads of access tokens for representative users in test resources (use a tool like https://jwt.io to easily get those payloads).
These starters are designed to push auto-configuration one step further. In most cases, you should need 0 Java conf. An effort was made to make [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials), Javadoc and modules READMEs as informative as possible. Please refer there for more details. Additionally refer to [module, dependency, class and other diagrams](https://sourcespy.com/github/ch4mpyspringaddons/) for a general overview of the repository.

## 3. <a name="start"/>Where to Start
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

## 4. <a name="versions"/>Versions & Requirements
6.x and 7.X branch are designed for spring-boot 3 and requires JDK 17 as minimum.

I could forget to update README before releasing, so please refer to [maven central](https://repo1.maven.org/maven2/com/c4-soft/springaddons/spring-addons/) to pick latest available release
```xml
    <properties>
        <springaddons.version>7.3.0</springaddons.version>
    </properties>
    <dependencies>

        <!-- to pull addons stater with its companion for unit-tests -->
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-starter-oidc</artifactId>
            <version>${springaddons.version}</version>
        </dependency>
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-starter-oidc-test</artifactId>
            <version>${springaddons.version}</version>
            <scope>test</scope>
        </dependency>

        <!-- If you don't want to use the starter but need test annotations -->
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-oauth2-test</artifactId>
            <version>${springaddons.version}</version>
            <scope>test</scope>
        </dependency>

    </dependencies>
```

## 5. <a name="release-notes"/>Release Notes
2.0 comes with a noticeable amount of breaking changes. So lets start tracking features.
- [`7.x` Branch](#release-notes-7) contains a single starter for all scenarios (reactive / servlet, client / resource server, JWT decoder / introspection). Compatible with Spring 6.1.x (Boot 3.1.x) and as so requires JDK 17 or above.
- [`6.x` Branch](#release-notes-6) contains 6 different starters `spring-addons-{webmvc|webflux}-{jwt-resource-server|introspecting-resource-server|client}`. Compatible with Spring 6.1.x (Boot 3.1.x) and as so requires JDK 17 or above.
- [`5.x` Branch](#release-notes-5) is compatible with Spring 5, Boot 2, Keycloak adapters for Spring and JDKs down to 1.8 but is not maintained anymore.

### 5.1. <a name="release-notes-7"/>`7.x` Branch

#### `7.3.0`
- [gh-166](https://github.com/ch4mpy/spring-addons/issues/166)
  * `@WithMockJwtAuth` authentication factory uses the authentication converter in the context or a `JwtAuthenticationConverter` if none is found
  * `@WithMockBearerTokenAuthentication` authentication factory uses the `OpaqueTokenAuthenticationConverter` in the context
- [gh-169](https://github.com/ch4mpy/spring-addons/issues/169) Per request post-login and post-logout URIs. It is now possible to set post-login success / failure URIs as header or request param when initiating `oauth2Login`. This URIs are saved in session and used by the default authentication success / failure handlers. Similarly, when using RP-Initiated Logout, the default logout success handler scans for a post-logout URI in headers and query params to override the default value in properties. The name for these headers, query params and session attributes are exposed by [SpringAddonsOidcClientProperties](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-starter-oidc/src/main/java/com/c4_soft/springaddons/security/oidc/starter/properties/SpringAddonsOidcClientProperties.java).

#### `7.1.16`
- Spring boot `3.2.0` as transient dependency

#### `7.1.15`
- [gh-155](https://github.com/ch4mpy/spring-addons/issues/155) Configurable HTTP status for responses to authorization_code flow initiation, authorization-code callback and logout. This makes BFF configuration easier for single page and mobile applications. Default OAuth2 response status (`302 Found`) can be overriden with:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        client:
          oauth2-redirections:
            pre-authorization-code: FOUND
            post-authorization-code: FOUND
            rp-initiated-logout: ACCEPTED
```
A per-request override can be done by setting `X-RESPONSE-STATUS` header with either a status code or label (for instance, both `201` and `ACCEPTED` are accepted as value).

#### `7.1.14`
- update CSRF configuration for SPAs as instructed by spring-security team in https://github.com/spring-projects/spring-security/issues/14125 

#### `7.1.13`
- [gh-153](https://github.com/ch4mpy/spring-addons/issues/153) have the default opaque tokens introspector accept `Integer`, `Long`, `Instant` and `Date` as value type for `iat` and `exp` claims

#### `7.1.12`
- Spring boot `3.1.5` as transient dependency
- [gh-151](https://github.com/ch4mpy/spring-addons/issues/151) scan application context for `authenticationEntryPoint` and `accessDeniedHandler` to auto-configure resource servers (default returns `401` for unauthorized requests instead of `302 redirect to login`).

#### `7.1.9`
- Spring boot `3.1.4` as transient dependency
- [gh-147](https://github.com/ch4mpy/spring-addons/issues/147) prevent addons test security conf to be auto-configured (complicates integration testing with test containers)

#### `7.1.8`
- Fix servlet resource server with introspection auto-configuration

#### `7.1.7`
- Enable to configure post-login and post-logout host (defaulted to client URI for backward compatibility)

#### `7.1.5`
- Spring Boot 3.1.3

#### `7.1.4`
- [gh-144](https://github.com/ch4mpy/spring-addons/issues/144) remove useless dependency on spring-session.

#### `7.1.1`
- Remove Back-Channel Logout experimental support. Follow the [PR on Spring Security](https://github.com/spring-projects/spring-security/pull/12570) for official support.
- Multi-tenancy support on OAuth2 clients is now optional and disabled by default. Set `com.c4-soft.springaddons.oidc.client.multi-tenancy-enabled=true` to keep it activated.
- [gh-140](https://github.com/ch4mpy/spring-addons/issues/140): use AOP instead of custom authorized-client repositories to support multi-tenancy on OAuth2 clients. That way, any configured authorized-client repository is instrumented (no need to proxy or extend spring-addons one).

#### `7.0.8`
- client `SecurityFilterChain` with `LOWEST_PRIORITY - 1` (instead of `HIGHEST_PRIORITY + 1`)
- `WWW_Authenticate` header with `Bearer` value for resource servers unauthorized requests (instead of `Basic`)

#### `7.0.7`
- Spring Boot 3.1.2
- force usage of `AntPathRequestMatcher` when defining `permit-all` in servlet implementations because of https://spring.io/security/cve-2023-34035 (Spring `6.1.2`)

#### `7.0.6`
- Fix a confusion between user subject and principal name in `SpringAddons(Server)OAuth2AuthorizedClientRepository` which could cause an authorized client not to be found when using another claim than subject as principal name.

#### `7.0.3`
- Fix the condition to add a filter inserting CSRF protection cookie to responses

#### `7.0.0`
See the [migration guide](https://github.com/ch4mpy/spring-addons/blob/master/7.0.0-migration-guide.md)
- merge all 6 starters into a single one
- reduce test libs count to 2: one with just annotations and another to ease testing of apps using the starter


### 5.2. <a name="release-notes-6"/>`6.x` Branch

#### `6.2.3`
- Spring Boot 3.1.3

#### `6.2.2`
- force usage of `AntPathRequestMatcher` when defining `permit-all` in servlet implementations because of https://spring.io/security/cve-2023-34035 (Spring `6.1.2`)

#### `6.2.1`
- Spring Boot 3.1.2
- Fix a confusion between user subject and principal name in `SpringAddons(Server)OAuth2AuthorizedClientRepository` which could cause an authorized client not to be found when using another claim than subject as principal name.

#### `6.2.0`
- remove `OAuth2AuthenticationFactory`: instead, use `Converter<Jwt, ? extends AbstractAuthenticationToken>`, `Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>`, `OpaqueTokenAuthenticationConverter` or `ReactiveOpaqueTokenAuthenticationConverter`
- create `@WithJwt` to build OAuth2 `Authentication` during tests, using a JSON string or file on the classpath and submitting it to the JWT authentication converter. All samples and tutorials are updated with this new annotation.
- deprecate `@WithMockJwt` and `@OpenId` (use the new `@WithJwt` instead)
- remove the archetypes

#### `6.1.16`
- [gh-133](https://github.com/ch4mpy/spring-addons/issues/133) Add a property to auto-configure an `audience` JWT validator (if present, the `aud` claim in the token will be checked to contain the URI provided in the conf)

#### `6.1.15`
- [gh-129](https://github.com/ch4mpy/spring-addons/issues/129) Auto-configure (with application properties) additional parameters for authorization-code request. This allows, for instance, to send an `audience` as required by Auth0. Additional parameters are defined for each client registration. In the following sample, `client-registration` `a` and `b` references an existing entries in spring.security.oauth2.client.registration:
```yaml
com:
  c4-soft:
    springaddons:
      security:
        client:
          authorization-request-params:
            client-registration-a:
            - name: audience
              value: demo.c4-soft.com
            client-registration-b:
            - name: kc_idp_hint
              value: google
            - name: machin
              value: chose
```

#### `6.1.14`
- [gh-128](https://github.com/ch4mpy/spring-addons/issues/128) add `@ClasspathClaims` to load claims from a JSON file in the classpath (test resources for instance).
```java
@Test
@WithMockJwtAuth(
  authorities = "ROLE_AUTHORIZED_PERSONNEL",
  claims = @OpenIdClaims(
    usernameClaim = "$['https://c4-soft.com/user']['name']",
    jsonFile = @ClasspathClaims("ch4mp.json")))
void givenUserIsAuthenticatedWithJsonClaims_whenGetClaims_thenOk() throws Exception {
  api.get("/greet").andExpect(status().isOk()).andExpect(content().string("Hello Ch4mp! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
}
```
- [gh-127](https://github.com/ch4mpy/spring-addons/issues/127) add a `json` property to @OpenIdClaims to define all claims with a JSON string
```java
@WithMockJwtAuth(
authorities = { "ROLE_AUTHORIZED_PERSONNEL" },
claims = @OpenIdClaims(
  usernameClaim = "$['https://c4-soft.com/user']['name']",
  json = """
{
  "https://c4-soft.com/user": {
    "name": "Ch4mp",
    "email": "ch4mp@c4-soft.com"
  },
  "aud": "https://localhost:7082"
}"""))
```

#### `6.1.13`
- [gh-125](https://github.com/ch4mpy/spring-addons/issues/125) Split claims used as `GrantedAuthority` source on comma and space (for instance, `scope` claim is usually a single string with comma separated scopes).

#### `6.1.12`
- [gh-122](https://github.com/ch4mpy/spring-addons/issues/122) Support for parametrized OAuth2 Authentications in `@ParameterizedTest`. In the following sample, **mind the `@JwtAuthenticationSource`** (decoring test) **and `@ParameterizedJwtAuth`** (decoring test method parameter). The first annotation defines the different authentication instances, the second inserts the one for the current test in the security context and provides it as test method parameter:
```java
@ParameterizedTest
@JwtAuthenticationSource({ @WithMockJwtAuth("NICE"), @WithMockJwtAuth("VERY_NICE") })
void givenUserIsGrantedWithAnyNiceAuthority_whenGetRestricted_thenOk(@ParameterizedJwtAuth JwtAuthenticationToken auth) throws Exception {
	api.perform(get("/restricted"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.body").value("You are so nice!"));
}
```
  The above will run two distinct tests in  sequence, one with each of the provided `@WithMockJwtAuth`. Same for:
  * `@WithMockBearerTokenAuthentication` with `@BearerAuthenticationSource` and `@ParameterizedBearerAuth`
  * `@OpenId` with `@OpenIdAuthenticationSource` and `@ParameterizedOpenId`
  * `@WithOAuth2Login` with `@OAuth2LoginAuthenticationSource` and `@ParameterizedOAuth2Login`
  * `@WithOidcLogin` with `@OidcLoginAuthenticationSource` and `@ParameterizedOidcLogin`

#### `6.1.11`
- Spring Boot 3.1.0

#### `6.1.10`
- Spring Boot 3.0.7

#### `6.1.9`
- [gh-112](https://github.com/ch4mpy/spring-addons/issues/112) fix CSRF token exposed to Javascript in servlets applications. Thanks to @giovannicandido for spotting and fixing this.

#### `6.1.8`
- Spring Boot 3.0.6

#### `6.1.7`
- create `ServletConfigurationSupport` and `ReactiveConfigurationSupport` in `spring-addons-{webmvc|webflux}-core` to remove code duplication from starters

#### `6.1.5`
- add new helpers to type private claims in test annotations for `Double`, `URIs`, `URLs` and `Date`
- add 1 level of nested claims to `@Claims`, the test annotation to define private claims in OAuth2 test annotations. It is not possible to describe recursive structures with annotation (annotation with a node of the same type as itself), which is an issue to describe a JSON document. To configure further nested claims, it is still possible to use `@JsonObjectClaim` with serialized JSON strings. Sample usage with all possible types of claims (hopefully, it will never be necessary to configure as many claims in a single test):
```java
@WithMockJwtAuth(authorities = "ROLE_AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(sub = "Ch4mpy", otherClaims = @Claims(
        intClaims = { @IntClaim(name = "int1", value = 42), @IntClaim(name = "int2", value = 51) },
        longClaims = { @LongClaim(name = "long1", value = 42), @LongClaim(name = "long2", value = 51) },
        doubleClaims = { @DoubleClaim(name = "double1", value = 4.2), @DoubleClaim(name = "double2", value = 5.1) },
        stringClaims = { @StringClaim(name = "str1", value = "String 1"), @StringClaim(name = "str2", value = "String 2") },
        uriClaims = { @StringClaim(name = "uri1", value = "https://localhost:8080/greet"), @StringClaim(name = "uri2", value = "https://localhost:4200/home#greet") },
        urlClaims = { @StringClaim(name = "url1", value = "https://localhost:8080/greet"), @StringClaim(name = "url2", value = "https://localhost:4200/home") },
        epochSecondClaims = { @IntClaim(name = "epoch1", value = 1670978400), @IntClaim(name = "epoch2", value = 1680648172)},
        dateClaims = { @StringClaim(name = "date1", value = "2022-12-14T00:40:00.000+00:00"), @StringClaim(name = "date1", value = "2023-04-04T00:42:00.000+00:00") },
        stringArrayClaims = { @StringArrayClaim(name = "strArr1", value = { "a", "b", "c" }), @StringArrayClaim(name = "strArr2", value = { "D", "E", "F" }) },
        jsonObjectClaims = { @JsonObjectClaim(name = "obj1", value = obj1), @JsonObjectClaim(name = "obj2", value = obj2)},
        jsonObjectArrayClaims = @JsonObjectArrayClaim(name = "objArr1", value = { obj3, obj4}),
        nestedClaims = { @NestedClaims(
                name = "https://c4-soft.com/user",
                intClaims = { @IntClaim(name = "nested_int1", value = 42), @IntClaim(name = "nested_int2", value = 51) },
                longClaims = { @LongClaim(name = "nested_long1", value = 42), @LongClaim(name = "nested_long2", value = 51) },
                doubleClaims = { @DoubleClaim(name = "nested_double1", value = 4.2), @DoubleClaim(name = "nested_double2", value = 5.1) },
                stringClaims = { @StringClaim(name = "nested_str1", value = "String 1"), @StringClaim(name = "nested_str2", value = "String 2") },
                uriClaims = { @StringClaim(name = "nested_uri1", value = "https://localhost:8080/greet"), @StringClaim(name = "nested_uri2", value = "https://localhost:4200/home#greet") },
                urlClaims = { @StringClaim(name = "nested_url1", value = "https://localhost:8080/greet"), @StringClaim(name = "nested_url2", value = "https://localhost:4200/home") },
                epochSecondClaims = { @IntClaim(name = "nested_epoch1", value = 1670978400), @IntClaim(name = "nested_epoch2", value = 1680648172)},
                dateClaims = { @StringClaim(name = "nested_date1", value = "2022-12-14T00:40:00.000+00:00"), @StringClaim(name = "nested_date1", value = "2023-04-04T00:42:00.000+00:00") },
                stringArrayClaims = { @StringArrayClaim(name = "nested_strArr1", value = { "a", "b", "c" }), @StringArrayClaim(name = "nested_strArr2", value = { "D", "E", "F" }) },
                jsonObjectClaims = { @JsonObjectClaim(name = "nested_obj1", value = obj1), @JsonObjectClaim(name = "nested_obj2", value = obj2)},
                jsonObjectArrayClaims = @JsonObjectArrayClaim(name = "nested_objArr1", value = { obj3, obj4}))})))
```

#### `6.1.4`
- gh-106: Properties to disable spring-addons security filter-chain auto-configuration:
  * for clients: empty path-matchers array or `com.c4-soft.springaddons.security.client.enabled=false`
  * for resource servers: `com.c4-soft.springaddons.security.enabled=false`

#### `6.1.3`
- fix CSRF protection configuration (apply https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_a_single_page_application_with_cookiecsrftokenrepository and https://docs.spring.io/spring-security/reference/5.8/migration/reactive.html#_i_am_using_angularjs_or_another_javascript_framework)
- rework the Javadoc and README of all 6 OAuth2 starters
- introduce a Back-Channel Logout client implementation to both client starters
- rework BFF and resource server & client tutorials with spring-addons client starters

#### `6.1.2`
- boot 3.0.4
- add a BFF tutorial

#### `6.1.1`
- add [spring-addons-webmvc-client](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-addons-webmvc-client)
- add [spring-addons-webflux-client](https://github.com/ch4mpy/spring-addons/tree/master/webflux/spring-addons-webflux-client)
- in both client starters, add a logout handler for OP with RP-Initiated logout implementations which do not comply with OIDC standard. This handler is configurable from properties (logout end-point and post-logout URIs). See [`resource-server_with_ui` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui) for details.

#### `6.1.0`
- **breaking change in properties:** authorities mapping is now configured per claim JSON path (instead of per issuer). This enables to use different prefix (and case) for different claims (for instance `SCOPE_` for `scope` claim and `ROLE_` for `realm_access.roles` one). As a consequence, `com.c4-soft.springaddons.security.issuers[].authorities.claims[]` is replaced with `com.c4-soft.springaddons.security.issuers[].authorities[].path`.Also, `prefix` as well as `case` are put at the same level as (JSON) `path`.

Sample migration with YAML:
```yml
com:
  c4-soft:
    springaddons:
      security:
        issuers:
        - location: ${keycloak-issuer}
          username-claim: preferred_username
          authorities:
            prefix: ROLE_
            claims:
            - realm_access.roles
            - resource_access.client1.roles
```
Becomes:
```yml
com:
  c4-soft:
    springaddons:
      security:
        issuers:
        - location: ${keycloak-issuer}
          username-claim: $.preferred_username
          authorities:
          - path: $.realm_access.roles
            prefix: ROLE_
          - path: $.resource_access.client1.roles
            prefix: ROLE_
```
- "pseudo" JSON path for username and authorities claims is now actual JSON path. This means that `$.resource_access.*.roles` will be successfully accepted. Thanks to JSON path syntax, this is not a breaking change (`$.resource_access.client1.roles` and `resource_access.client1.roles` are interpreted the same)
- bump to Spring Boot 3.0.3

#### `6.0.16`
- Add a `username-clame` configuration property to define, per issuer, from which claim of the access token should be retrieved the username (what is returned by `Authentication::getName`). Default is subject for backward compatibility

#### `6.0.15`
- [gh-100](https://github.com/ch4mpy/spring-addons/issues/100) prevent a NPE in reactive resource-server using JWT spring-addons starter when the issuer in an access token is not listed in conf. All credits go to [lArtiquel](https://github.com/lArtiquel) who spotted the bug and submitted the fix.

#### `6.0.13`
- create `ServerHttpRequestSupport` and `HttpServletRequestSupport` to help statically access to the request in current context (usage in authentication converters for instance

#### `6.0.12`
- add `@WithOAuth2Login` and `@WithOidcLogin` to populate test security-context with an `OAuth2AuthenticationToken` instance (with respectively `DefaultOAuth2User` and `DefaultOidcUser` as principal)
- bump to spring-boot `3.0.2`
- default authorities collection in tests annotations, `MockMvc` post-processors and `WebTestClient` mutators is set to empty array (instead of `{ "ROLE_USER" }`)

#### `6.0.11`
- [gh-86](https://github.com/ch4mpy/spring-addons/issues/86) `OAuthentication::setDetails` [should not throw](https://github.com/spring-projects/spring-security/issues/11822) until spring-security 6.1 is released
- [gh-87](https://github.com/ch4mpy/spring-addons/issues/87) spring-addons JWT starters should start even if `spring.security.oauth2.resourceserver.jwt.issuer-uri` is set in configuration properties

#### `6.0.10`
- [gh-83](https://github.com/ch4mpy/spring-addons/issues/83) do not force traffic to http when SSL is not enabled (just force https when SSL is enabled)

#### `6.0.9`
- Make OAuthentication immutable

#### `6.0.7`
- release with spring-boot 3.0.0 GA as transitive dependency

#### `6.0.1`
- [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) for all combinations of:
  * webmvc / webflux
  * JWT decoder / access token introspection
  * `OAuthentication<OpenidClaimSet>` / Spring default `Authentication` implementation (`JwtAuthenticationToken` for JWT decoder or `BearerTokenAuthentication` for token introspection)
- minor fixes (@WithMockAuthentication and reactive + introspection starter)

#### `6.0.0`
- Switch to spring-boot 3 (and spring-security 6)
- Stop supporting the [very deprecated Keycloak libs for spring](https://github.com/keycloak/keycloak/discussions/10187)

### 5.3. <a name="release-notes-5"/>`5.x` branch
This branch is not maintained anymore. Only versions compatible with Spring 6.1.x (Boot 3.1.x) and JDK >= 17 are maintained.

#### `5.4.2`
- [gh-100](https://github.com/ch4mpy/spring-addons/issues/100) prevent a NPE in reactive resource-server using JWT spring-addons starter when the issuer in an access token is not listed in conf. All credits go to [lArtiquel](https://github.com/lArtiquel) who spotted the bug and submitted the fix.

#### `5.4.0`
- Use a single bean name for
  * `ServletSecurityBeans` and `ReactiveSecurityBeans`: AddonsSecurityBeans
  * `@AutoConfigureAddonsSecurity{Webmvc|Weblux}{Jwt|Introspecting}`: `@AutoConfigureAddonsSecurity`
- Add `@AutoConfigureAddonsWebSecurity` to do the same as existing `@AutoConfigureAddonsSecurity` which now loads authorities converter only (useful to unit-test @Components that are not @Controller).
- More options for CSRF configuration (enum property instead of a boolean) and CSRF disabled by default when session-management is state-less.
- Compatibility with JDK 1.8 and spring-boot 2.6 (get version 6.x for spring-boot 3 and JDK 17)
- webflux dependencies cleanup (were pulling some servlet dependencies)
- All samples now demo @Service and @Repository unit-tests in addition to @Controller ones.

#### `5.3.0`
Use `JwtAuthenticationToken` or `BearerAuthenticationToken` by default in  resource-server starters. For some reason, `OAuthentication<OpenidClaimSet>` frightens rookies.
- make `OAuth2AuthenticationFactory` `@Bean` optional.
- remove `OAuth2ClaimsConverter` (interface definition and @ConditionalOnMissingBean)
- remove the recently added `oauth2-authentication-factory-enabled` property (instead, evaluate if an `OAuth2AuthenticationFactory` bean was provided)

#### `5.2.2`
- resource-server starter main beans (`Security(Web)FilterChain`) are no-longer "conditional on missing": if you dan't want it, don't pull starter lib.
- add `oauth2-authentication-factory-enabled` flag to easily fall-back to Spring default OAuth2 `Authentication` implementations (`JwtAuthenticationToken` and `BearerTokenAuthentication` for resource-servers with respectively JWT decoder or opaque token introspection)

#### `5.1.3`
- keycloak 19
- release with JDK 17 and boot 2.7.2
- release with JDK 1.8 and boot 2.6.10

#### `5.1.0`
- Support token introspection for resource-servers.
- Rename `spring-addons-*-jwt-resource-server-test` to `spring-addons-*-test` as it apply for both JWT and introspection

#### `5.0.0`
Rename modules to:
- have all module names start with `spring-addons` prefix, then intermediate module if any (`archetypes`, `samples`, `starters`, `webmvc` or `webflux`) and last what leaf module aims at
- better reflect what it does

For instance, `spring-security-oauth2-webmvc-addons` only applies to resource-servers secured with JWTs (not to opaque tokens) -> renamed to `spring-addons-webmvc-jwt-resource-server`

Rename `com.c4-soft.springaddons.security.token-issuers` configuration properties to `com.c4-soft.springaddons.security.issuers` for the same reason: only accepts JWT token issuers (and not opaque token issuers with introspection end-point for instance)

#### `4.5.0`
CSRF enabled by default, using `CookieCsrfTokenRepository` if session management is "stateless".

#### `4.4.4`
[gh-53 GenericMethodSecurityExpressionHandler should accept expression root suppliers for many authentication type](https://github.com/ch4mpy/spring-addons/issues/53)

#### `4.4.2`
add [reCAPTCHA validation spring-boot starter](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starters-recaptcha)

#### `4.4.1`
rename `@WithMockOidcAuth` to shorter and more expressive `@OpenId`: it populates test security context with an OAuth2 `Àuthentication` containing an OpenID claim-set

#### `4.4.0`
- rename `OpenidClaimSet` to `OpenidClaimSet`: more expressive as this class contains OpenID token claims only
- rename `OAuthentication` to `OAuthentication`: it has no more adherence to OpenID (just specific to authentication with encoded claims in a bearer string)

#### `4.3.2`
Slight properties rework. Now, to configure issuers and authorities mapping:
```
# should be set to where your authorization-server is
com.c4-soft.springaddons.security.issuers[0].location=https://localhost:8443/realms/master

# should be configured with a list of private-claims this authorization-server puts user roles into
# below is default Keycloak conf for a `spring-addons` client with client roles mapper enabled
com.c4-soft.springaddons.security.issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons-public.roles,resource_access.spring-addons-confidential.roles

# use IDE auto-completion or see SpringAddonsSecurityProperties javadoc for complete configuration properties list
```
where `caze` is one of `unchanged`, `upper` or `lower`

#### `4.3.0`
- [gh-50](https://github.com/ch4mpy/spring-addons/issues/50): One entry per authorization-server for authorities mapping (see samples `application.properties` files for new configuration structure).
- [gh-51](https://github.com/ch4mpy/spring-addons/issues/51): Group archetypes, webmvc and webflux modules.

#### `4.2.1`
- [gh-49](https://github.com/ch4mpy/spring-addons/issues/49): Samples in dedicated modules. All samples are moved from libs tests to [`samples`](https://github.com/ch4mpy/spring-addons/tree/master/samples) module, with one sub-module per sample.

#### `4.2.0`
Cleanup and prepare for spring-boot 3:
- [gh-46](https://github.com/ch4mpy/spring-addons/issues/46): split webmvc & webflux content from `spring-addons-oauth2` 
- [gh-47](https://github.com/ch4mpy/spring-addons/issues/47): provide `SecurityFilterChain` bean instead of extending `WebSecurityConfigurerAdapter`
- [gh-48](https://github.com/ch4mpy/spring-addons/issues/48): make use of spring-boot `@AutoConfiguration`

#### `4.1.5`
- Replace multiple JWT issuers JwtDecoder (from 4.1.4) with `AuthenticationManagerResolver` @Beans 

#### `4.1.4`
- JwtDecoder for configuring multiple JWT issuers (single resource server accepting IDs from two or more authorization-servers)

#### `4.1.3`
- finer configuration control with `SpringAddonsSecurityProperties`

#### `4.0.0`
- move keycloak related code to `spring-addons-keycloak`

#### `3.2.0`
- Master branch back to single JDK: 17
- Create `jdk1.8` and `jdk11` branches

#### `3.1.16`
- Add [spring-addons-archetypes-webmvc-multimodule](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-archetypes-webmvc-multimodule) to boostrap native-ready Spring REST API with webmvc, JPA, OpenAPI and OpenID security.

#### `3.1.13`
- Add a [sample](https://github.com/ch4mpy/spring-addons/blob/master/custom-oidc-authentication-impl.MD) with `OpenidClaimSet` specialisation (parse private claims in addition to authorities).

#### `3.1.12`
- Improve `OidcReactiveApiSecurityConfig` and `OidcServletApiSecurityConfig` usability: ease security beans replacement (including authorities and authentication converter for use cases where OAuthentication is not enough)

#### `3.1.11`
- Rename `SecurityProperties` to less conflicting `SpringAddonsSecurityProperties`

#### `3.1.10`
- Turn `AbstractOidc...ApiSecurityConfig` into `Oidc...ApiSecurityConfig` with default authorities mapper being keycloak or Auth0 depending on `com.c4-soft.springaddons.security.keycloak.client-id` being set or not
- More CORS and authorities mapping configuration in `SecurityProperties`

#### `3.1.8`
- Fix missing JTI claim mapping from `@OpenIdClaims` ([gh-35](https://github.com/ch4mpy/spring-addons/issues/35)).

#### `3.1.7`
- Add `AbstractOidcReactiveApiSecurityConfig` to `spring-addons-oauth2`. It provides with reasonable default WebSecurityConfig for a reactive (weblux) based API secured with OAuthentication.

#### `3.1.6`
- Add `AbstractOidcServletApiSecurityConfig` to `spring-addons-oauth2`. It provides with reasonable default WebSecurityConfig for a servlet based API secured with OAuthentication.

#### `3.1.4`
- lombok with provided scope ([gh-31](https://github.com/ch4mpy/spring-addons/issues/31))

#### `3.1.3`
- spring-boot 2.6.1
- release with JDK version (compilation and runtime target)

#### `3.1.0`
- spring-boot 2.6

#### `3.0.0`
- in OAuth2 related test annotations all claims are now grouped under a single `claims = @OpenIdClaims(...)`
- `@WithMockJwtAuth` in addition to `@WithMockKeycloakAuth` and `@WithMockOidcAuth`
- some code cleanup, quite a bunch of code removed and some renaming (including breaking changes, reason for new major version)

#### `2.6.6`
- import spring-boot 2.5.5 BOM (instead of inheriting 2.5.4 POM)

#### `2.6.5`
- Downgrade Java compatibility to 1.8

#### `2.6.1`
- spring-boot 2.5.4

#### `2.6.0`
- replace `KeycloakOidcIdAuthenticationConverter` with `SynchronizedJwt2OidcIdAuthenticationConverter` and complement it with `ReactiveJwt2OidcIdAuthenticationConverter`
- remove references to Keycloak from `spring-addons-oauth2` (implementations where mostly useless)

#### `2.5.4`
- bump Keycloak BOM to 14.0.0

#### `2.5.3`
- bump spring-boot to 2.5

#### `2.5.1`
- introduce `@JsonObjectClaim` and `@JsonArrayClaim` to configure complex private claims. Sample: `@WithMockKeycloakAuth(otherClaims = @ClaimSet(jsonObjectClaims = @JsonObjectClaim(name = "foo", value = "{\"bar\":\"bad\", \"nested\":{\"deep\":\"her\"}, \"arr\":[1,2,3]}")))` or `@WithMockOidcId(privateClaims = @JsonObjectClaim(name = "foo", value = "{\"bar\":\"bad\", \"nested\":{\"deep\":\"her\"}, \"arr\":[1,2,3]}"))`

#### `2.4.1`
- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) added jti and nbf (from JWT spec) to @IdTokenClaims (an ID token is a JWT)
- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) added session_state to @IdTokenClaims as per https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions
- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) rename `privateClaims` to `otherClaims` in `@WithMockKeycloakAuth`
- [issue #15](https://github.com/ch4mpy/spring-addons/issues/15) `GrantedAuthoritiesMapper` is now optional in test config. Defaulted to `NullAuthoritiesMapper`

#### `2.4.0`
- rename `ServletKeycloakAuthUnitTestingSupport::keycloakAuthenticationToken()` to `authentication()` to improve API fluidity (`api.with(keycloak.authentication()).get(...)`)

#### `2.3.0`
- implementation closer to [open ID specs](https://openid.net/specs/openid-connect-core-1_0.html): split claims into `@IdTokenClaims` and `@OidcStandardClaims`
- re-use OIDC ID annotations into `@WithMockKeycloakAuth`

#### `2.2.0`
- `OidcId::getName()` returns `subject` claim instead of `preferred_username`
- replace `name` with `subject` in `@WithMockOidcId`
- replace `name` from `@WithMockKeycloakAuth` with `preferedUsername` in `@WithAccessToken`
- support for private claims in `@WithMockOidcId` and `@WithMockKeycloakAuth` (claims with values of type `int`, `long`, `String` and `String[]` only)
- add missing subject claim in Keycloak access and ID tokens
- compose `@WithAccessToken` with `@WithKeycloakIDToken` instead of repeating properties (`AccessToken` extends `IDToken`)
- add advanced `@WithMockKeycloakAuth` sample usage in [`spring-addons-oauth2-test` README](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test)

#### `2.1.0`
- fix Keycloak typo (was wrongly spelled Keycloack at many places)
- add samples with authorities retrieved from a DB instead of the JWT for both OAuthentication and JwtAuthenticationToken
- add sample involving `keycloak-spring-boot-starter` and `keycloak-spring-security-adapter`

#### `2.0.0`
This release is still focused on unit-testing Spring OAuth2 applications

- `@WithMockAuthentication` annotation along with `mockAuthentication()` servlet (webmvc) and reactive (webflux) flow APIs. You choose the `Authentication` type, the framework feeds the security context with a Mockito mock. This is dead simple but should cover 99% of test cases. I wonder why I didn't think of it sooner...
- Focus solely on adding to Spring `Authentication` implementations and tests tooling (no more alternatives, with an exception for `OidcId` which overlaps Spring's `OidcIdToken`)
- Split `webmvc` (servlets) and `webflux` (reactive) code in distinct libs to ease dependency management
- Re-shuffle packages and jars (less code, less jars, more expressive package names)
- WIP: Extensives samples and tests. Samples are boot apps under `src/test` to keep jars small
- Use Keycloak as authorisation-server for all resource-server samples, each of which configuring a specific `Authentication` impl

Note that I chose Keycloak because it's a feature rich, easy to setup authorisation-server.
It should not be much of an effort to migrate sample resource-servers to another one, with an exception to those using `KeycloakAuthenticationToken` as authentication impl, of course.

## 6. <a name="maven-central"/>Maven-Central Reminders

Cheat-sheets for me when setting up a new development environment

### 6.1. GPG Sign Key
``` bash
gpg --list-keys
# if key absent, then generate one with
gpg --gen-key
# publish public key to one of supported servers 
export GPG_PUB_KEY=(replace with "pub" key)
gpg --keyserver http://pgp.mit.edu:11371/ --send-keys $GPG_PUB_KEY
gpg --keyserver http://keyserver.ubuntu.com:11371/ --send-keys $GPG_PUB_KEY
gpg --keyserver https://keys.openpgp.org/ --send-keys $GPG_PUB_KEY
```


### 6.2. ~/.m2/settings.xml
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
  <servers>
    <server>
      <!-- OSSRH Jira account -->
      <id>ossrh</id>
      <username>ch4mpy</username>
      <password>${env.OSSRH_PWD}</password><!-- password retrieved from environment variable -->
    </server>
  </servers>

  <profiles>
    <profile>
      <id>ossrh</id>
      <activation>
        <activeByDefault>true</activeByDefault>
      </activation>
      <properties>
        <gpg.executable>gpg</gpg.executable>
        <gpg.passphrase>${env.GPG_PWD}</gpg.passphrase><!-- password retrieved from environment variable -->
      </properties>
    </profile>
  </profiles>
</settings>
```

Add-opens for releasing with JDK 17:
`export JDK_JAVA_OPTIONS='--add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.text=ALL-UNNAMED --add-opens java.desktop/java.awt.font=ALL-UNNAMED'`
