# Spring-addons

Do not hesitate to fork this repo and send pull requests, even for things as small as a typo in READMEs or Javadoc. This would promote you as contributor.

## Unit testing
There are 6 different unit-test libs you can pick from this repo:
- `spring-addons-keycloak` contains **@WithMockKeycloakAuth** for Keycloak spring adapters, but be aware that this [adapters are (very) deprecated](https://github.com/keycloak/keycloak/discussions/10187) and that you'd better use one of the resource-server starters from this repo (most probably `spring-addons-webmvc-jwt-resource-server`)
- `spring-addons-oauth2-test` contains other useful test annotations, among which 
  - **@WithMockJwtAuth** for apps configured with JWT decoder and Spring's default `Authentication` implementation
  - **@WithMockBearerTokenAuthentication** for apps configured with token introspection and Spring's default `Authentication` implementation
  - **@Openid** for apps configured with `OAuthentication<OpenidClaimSet>`, spring-addons default `Authentication` implementation
- `spring-addons-{webmvc|webflux}-{jwt|introspecting}-test`: are based on `spring-addons-oauth2-test`, adding:
  - tools for setting-up unit-tests context for apps depending on `spring-addons-{webmvc|webflux}-{jwt|introspecting}-resource-server`
  - `MockMvcSupport` or `WebTestClientSupport` which add shortcuts for building requests (for instance `get(url)` insteadof `perform(get("/greet")`), auto-activates `secure(true)` and `csrf()` if needed, and also ensures that registered serializers are used to (de)serialize payloads)

Sample for `@WithMockJwtAuth` with `spring-addons-oauth2-test`:
```java
@WebMvcTest(GreetingController.class)
@Import(WebSecurityConfig.class)
class GreetingControllerTest {

    @Autowired
    MockMvc mockMvc;
    
    @MockBean
    JwtDecoder jwtDecoder;

    @Test
    @WithMockJwtAut(
        authorities = { "NICE", "AUTHOR" },
        claims = @OpenIdClaims(preferredUsername = "Tonton Pirate")
    void whenNiceGuyThenCanBeGreeted() throws Exception {
        mockMvc
                .perform(get("/greet").secure(true).csrf())
                .andExpect(status().isOk())
                .andExpect(content().string("Hi Tonton Pirate!"));
    }
}
```

Sample for `@OpenId` with `spring-addons-webmvc-jwt-test`:
```java
@WebMvcTest(GreetingController.class)
@AutoConfigureAddonsSecurityWebmvcJwt
@Import(WebSecurityConfig.class)
class GreetingControllerTest {

    @Autowired
    MockMvcSupport mockMvc;

    @Test
    @OpenId(
        authorities = { "NICE", "AUTHOR" },
        claims = @OpenIdClaims(preferredUsername = "Tonton Pirate")
    void whenNiceGuyThenCanBeGreeted() throws Exception {
        mockMvc
                .get("/greet")
                .andExpect(status().isOk())
                .andExpect(content().string("Hi Tonton Pirate!"));
    }
}
```

## Spring-boot resource-server starters
This repo contains 4 starters which are (very) thin layers on top of `spring-boot-starter-oauth2-resource-server`. Each is composed of only one single auto-loaded configuration class with just a few beans and every setting can be overriden in your properties or web-security conf.

### What is added to `spring-boot-starter-oauth2-resource-server`
`spring-addons-{webmvc|webflux}-{jwt|introspecting}-resource-server` are not a replacement for `spring-boot-starter-oauth2-resource-server`.
It builds on top if it, adding following auto-configuration:
- support multiple OIDC authorization-server `issuer` URI: can configure as as many as you need for multi-tenant scenarios (applies to JWTs only)
- convenient granted-authorities mapping: source claims of course (not just `scope`), but also prefix and case processing
- fine grained CORS configuration (per path)
- 401 (unauthorized) instead of 302 (redirect to login) when authentication is missing or invalid on protected end-point
- enabled anonymous
- list of "permit-all" routes accessible to anonymous
- default security to `isAuthenticated()` (all routes which are not listed in "permit-all")
- "stateless" session management
- enabled CSRF (with `CookieCsrfTokenRepository` if session management is left state-less)

All that with **0 java config, 1 dependency and just a few properties**:
```properties
com.c4-soft.springaddons.security.issuers[0].location=https://localhost:8443/realms/master
com.c4-soft.springaddons.security.issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons-public.roles,resource_access.spring-addons-confidential.roles
com.c4-soft.springaddons.security.cors[0].path=/greet/**
com.c4-soft.springaddons.security.permit-all=/actuator/health/readiness,/actuator/health/liveness,/v3/api-docs/**
```

Bootyful, isn't it?

### Where to start
[Tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) which cover:
- just enough OAuth2 theory
- dev environment configuration (SSL certificate, Keycloak)
- various resource-servers security configuration scenarios
- security rules unit-testing

### What lib to pick
Pick one of the four possible combinations for `spring-addons-{webmvc|webflux}-{jwt|introspecting}-resource-server` where choices are:
  * **webmvc** for servlet apps VS **webflux** for reactive ones
  * **jwt** to configure a JWT decoder VS **introspecting** for token introspection 

### Auto-configured components customization
`spring-addons-{webmvc|webflux}-{jwt|introspecting}-resource-server` are spring-boot 2.7+ modules: a `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` defines what will be auto-configured.

Depending you chose `webmvc` or `webflux`, and `jwt` or `introspection` there are slight variations, but all wotk the same way:
- one configuration class is loaded: `ServletSecurityBeans` for servlets and `ReactiveSecurityBeans` for reactive apps.
- one main @Bean is configured: `SecurityFilterChain` for servlets and `SecurityWebFilterChain` for reactive apps.  It can not be overriden and your app shoudn't provide its own.
- most configuration is controlled from `SpringAddonsSecurityProperties` (source claims for authorities mapping, CORS, issuers, CSRF, etc.)
- a few `@ConditionalOnMissingBean` are exposed. Just define your own to override default behaviour:
  * `ExpressionInterceptUrlRegistryPostProcessor` (or `AuthorizeExchangeSpecPostProcessor` for reactive apps): defines security policy for all routes that are not listed in `permit-all` property. Default is `registry -> registry.anyRequest().authenticated()`
  * `HttpSecurityPostProcessor` (or `ServerHttpSecurityPostProcessor` for reactive apps): a Hook to override all or part of HttpSecurity auto-configuration. Called after spring-addons configuration was applied so that you can modify anything. Default is a no-opp.
  * `OAuth2ClaimsConverter<T extends Map<String, Object> & Serializable>`: converts `Map<String, Object>` claims to a more specific claim-set. Default is an OpenID claim-set, but you might use something aware of your authorization-server private claims (or standard if not OpenID).
  * `OAuth2AuthoritiesConverter`: retrieve authorities from access-token claims (directly or with the help of a `@Service`, `@Repository` or whatever you like)
  * `OAuth2AuthenticationFactory<T extends AbstractAuthenticationToken>`: Instantiate any `Authentication` of your choice from bearer string and token claims. Used only if `oauth2-authentication-factory-enabled` is `true` (otherwise default Spring implementations are used).
  * `ServerAccessDeniedHandler` (for reactive apps only): return 401 unauthorized when authorization header is invalid or missing (instead of 302 redirect to login)

Also, if you opt for a `jwt` starter, a JWT decoder is configured when `introspecting` starters configure resource-server for (opaque) token introspection instead.

## Versions
Master branch requires **JDK 17** as minimum. Spring version released in the coming quarter will too.

Starters are designed for **spring-boot 2.7** and after (boot auto-loading mechanisms have changed with 2.7).

There is a branch for JDK 1.8 and spring-boot before 2.7, but it isn't updated as often. You might explore [maven central](https://repo1.maven.org/maven2/com/c4-soft/springaddons/spring-addons/) to find which version are available.

I could forget to update README before releasing, so please refer to [maven central](https://repo1.maven.org/maven2/com/c4-soft/springaddons/spring-addons/) to pick latest available release
```xml
    <properties>
        <springaddons.version>5.2.2</springaddons.version>
        <app-type>webmvc</app-type><!-- alternative value is webflux !-->
        <token>jwt</token><!-- alternative value is introspecting !-->
    </properties>
    <dependencies>

        <!-- to pull resource-server stater with its companion for unit-tests -->
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-${app-type}-${token}-resource-server</artifactId>
            <version>${springaddons.version}</version>
        </dependency>
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-${app-type}-${token}-test</artifactId>
            <version>${springaddons.version}</version>
            <scope>test</scope>
        </dependency>

        <!-- If you don't want starters but need @WithMockJwtAuth or WithMockBearerTokenAuthentication -->
        <!-- instead of the two preceding, you can pull test annotations only -->
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-oauth2-test</artifactId>
            <version>${springaddons.version}</version>
        </dependency>

    </dependencies>
```

## modules

### [`samples`](https://github.com/ch4mpy/spring-addons/tree/master/samples) and [`tutorials`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials)
Provides samples for different security scenari, with **configuration and unit tests** for
- servlet or reactive apps
- spring's `JwtAuthenticationToken`, Keycloak's `KeycloakAuthenticationToken`, this repo `OAuthentication<OpenidClaimSet>`
- granted authorities retrieved from the token or from an external source (JPA repo in the sample but could be a web-service)
- usage of test annotations or "fluent API" (MockMvc request post-processors and WebTestClient mutators)

### [spring-addons-oauth2](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2)
Declined for webmvc: [spring-addons-webmvc-jwt-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-addons-webmvc-jwt-resource-server) and webflux: [spring-addons-webflux-jwt-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/webflux/spring-addons-webflux-jwt-resource-server)

Thin layer on top of spring-security resource-server libs which brings:
- spring-boot `@AutoConfiguration` for RESTful APIs. Defaults (which can be configured from `configuration.propeties`) are:
  - CORS enabled to all routes (a REST API is not intended to serve UI)
  - CSRF enabled (with `CookieCsrfTokenRepository` if session-management is state-less)
  - anonymous enabled (but authentication required to all routes that is not included in `permit-all` property)
  - authorities mapped from `realm_access.roles` with no transformation (no prefix, no case alteration)
  - stateless sessions
  - 401 (instead of redirection to login) if user is not authenticated (or authentication is invalid)
- `OpenidClaimSet`: basically a `Map<String, Object>` with accessors to OpenID standard claims
- an OAuth Authentication: `OAuthentication<T extends Map<String, Object>` to use with any authorization-server (Keycloak, MS identity-server, Auth0, ...)

### [spring-addons-keycloak](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-keycloak)

Contains the code depending on [depreacted](https://github.com/keycloak/keycloak/discussions/10187) Keycloak spring adapters.

Important note: You do **not** have to use `KeycloakAuthenticationToken` to authenticate your request against a Keycloak instance. Spring's `JwtAuthenticationToken`, this repo `OAuthentication<? extends OpenidClaimSet`, or an `Authentication` implementation of your own can do the job and would likely be more portable. See [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) for alternatives.

But if `@WithMockKeycloakAuth` is the only reason for you landing on this repo, then `spring-addons-keycloak` is the lib you are looking for.

### [archetypes](https://github.com/ch4mpy/spring-addons/tree/master/archetypes)
A set of archetypes for webflux and webmvc apps, initiated either as multi or single module maven projects.
All generate projects focused on REST micro-services:
- Servlet or reactive @RestController
- OpenID security
- default conf providing with enabled CORS, enabled CSRF with `CookieCsrfTokenRepository`, stateless sessions, 401 instead of redirect to login, ...
- Spring exception-handling
- spring-native for smaller / faster booted services
- bootstraped JPA and unit tests

### [starters](https://github.com/ch4mpy/spring-addons/tree/master/starters)
A set of re-usable `@Components` (mostly `@Service` and `@ConfigurationProperties`) with spring-boot `@AutoConfiguration`:
- [WebClient.Builder](https://github.com/ch4mpy/spring-addons/tree/master/starters/spring-addons-starters-webclient) factory  with proxy configuration from properties
- [reCAPTCHA](https://github.com/ch4mpy/spring-addons/tree/master/starters/spring-addons-starters-recaptcha)
Uses Webclient starter to provide with Google reCAPTCHA validation Service (secret & proxy configuration from properties)

Using such libs is dead simple: just declare depedency on one of those libs and use @Components just as if were declared in your app package (define properties and auto-wire components as usual in your boot project).

## Release notes

2.0 comes with a noticeable amount of breaking changes. So lets start tracking features.

## 5.2.2
- resource-server starter main beans (`Security(Web)FilterChain`) are no-longer "conditional on missing": if you dan't want it, don't pull starter lib.
- add `oauth2-authentication-factory-enabled` flag to easily fall-back to Spring default OAuth2 `Authentication` implementations (`JwtAuthenticationToken` and `BearerTokenAuthentication` for resource-servers with respectively JWT decoder or opaque token introspection)

## 5.1.3
- keycloak 19
- release with JDK 17 and boot 2.7.2
- release with JDK 1.8 and boot 2.6.10

## 5.1.0
- Support token introspection for resource-servers.
- Rename `spring-addons-*-jwt-resource-server-test` to `spring-addons-*-test` as it apply for both JWT and introspection

## 5.0.0
Rename modules to:
- have all module names start with `spring-addons` prefix, then intermediate module if any (`archetypes`, `samples`, `starters`, `webmvc` or `webflux`) and last what leaf module aims at
- better reflect what it do

For instance, `spring-security-oauth2-webmvc-addons` only applies to resource-servers secured with JWTs (not to opaque tokens) -> renamed to `spring-addons-webmvc-jwt-resource-server`

Rename `com.c4-soft.springaddons.security.token-issuers` configuration properties to `com.c4-soft.springaddons.security.issuers` for the same reason: only accepts JWT token issuers (and not opaque token issuers with introspection end-point for instance)

## 4.5.0
CSRF enabled by default, using `CookieCsrfTokenRepository` if session management is "stateless".

## 4.4.4
[gh-53 GenericMethodSecurityExpressionHandler should accept expression root suppliers for many authentication type](https://github.com/ch4mpy/spring-addons/issues/53)

## 4.4.2
add [reCAPTCHA validation spring-boot starter](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starters-recaptcha)

## 4.4.1
rename `@WithMockOidcAuth` to shorter and more expressive `@OpenId`: it populates test security context with an OAuth2 `Àuthentication` containing an OpenID claim-set

## 4.4.0
- rename `OpenidClaimSet` to `OpenidClaimSet`: more expressive as this class contains OpenID token claims only
- rename `OAuthentication` to `OAuthentication`: it has no more adherence to OpenID (just specific to authentication with encoded claims in a bearer string)

## 4.3.2
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

### 4.3.0
- [gh-50](https://github.com/ch4mpy/spring-addons/issues/50): One entry per authorization-server for authorities mapping (see samples `application.properties` files for new configuration structure).
- [gh-51](https://github.com/ch4mpy/spring-addons/issues/51): Group archetypes, webmvc and webflux modules.

### 4.2.1
- [gh-49](https://github.com/ch4mpy/spring-addons/issues/49): Samples in dedicated modules. All samples are moved from libs tests to [`samples`](https://github.com/ch4mpy/spring-addons/tree/master/samples) module, with one sub-module per sample.

### 4.2.0
Cleanup and prepare for spring-boot 3:
- [gh-46](https://github.com/ch4mpy/spring-addons/issues/46): split webmvc & webflux content from `spring-addons-oauth2` 
- [gh-47](https://github.com/ch4mpy/spring-addons/issues/47): provide `SecurityFilterChain` bean instead of extending `WebSecurityConfigurerAdapter`
- [gh-48](https://github.com/ch4mpy/spring-addons/issues/48): make use of spring-boot `@AutoConfiguration`

### 4.1.5
- Replace multiple JWT issuers JwtDecoder (from 4.1.4) with `AuthenticationManagerResolver` @Beans 

### 4.1.4
- JwtDecoder for configuring multiple JWT issuers (single resource server accepting IDs from two or more authorization-servers)

### 4.1.3
- finer configuration control with `SpringAddonsSecurityProperties`

### 4.0.0
- move keycloak related code to `spring-addons-keycloak`

### 3.2.0
- Master branch back to single JDK: 17
- Create `jdk1.8` and `jdk11` branches

### 3.1.16
- Add [spring-addons-archetypes-webmvc-multimodule](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-archetypes-webmvc-multimodule) to boostrap native-ready Spring REST API with webmvc, JPA, OpenAPI and OpenID security.

### 3.1.13
- Add a [sample](https://github.com/ch4mpy/spring-addons/blob/master/custom-oidc-authentication-impl.MD) with `OpenidClaimSet` specialisation (parse private claims in addition to authorities).

### 3.1.12
- Improve `OidcReactiveApiSecurityConfig` and `OidcServletApiSecurityConfig` usability: ease security beans replacement (including authorities and authentication converter for use cases where OAuthentication is not enough)

### 3.1.11
- Rename `SecurityProperties` to less conflicting `SpringAddonsSecurityProperties`

### 3.1.10
- Turn `AbstractOidc...ApiSecurityConfig` into `Oidc...ApiSecurityConfig` with default authorities mapper being keycloak or Auth0 depending on `com.c4-soft.springaddons.security.keycloak.client-id` being set or not
- More CORS and authorities mapping configuration in `SecurityProperties`

### 3.1.8
- Fix missing JTI claim mapping from `@OpenIdClaims` ([gh-35](https://github.com/ch4mpy/spring-addons/issues/35)).

### 3.1.7
- Add `AbstractOidcReactiveApiSecurityConfig` to `spring-addons-oauth2`. It provides with reasonable default WebSecurityConfig for a reactive (weblux) based API secured with OAuthentication.

### 3.1.6
- Add `AbstractOidcServletApiSecurityConfig` to `spring-addons-oauth2`. It provides with reasonable default WebSecurityConfig for a servlet based API secured with OAuthentication.

### 3.1.4
- lombok with provided scope ([gh-31](https://github.com/ch4mpy/spring-addons/issues/31))

### 3.1.3
- spring-boot 2.6.1
- release with JDK version (compilation and runtime target)

### 3.1.0
- spring-boot 2.6

### 3.0.0
- in OAuth2 related test annotations all claims are now grouped under a single `claims = @OpenIdClaims(...)`
- `@WithMockJwtAuth` in addition to `@WithMockKeycloakAuth` and `@WithMockOidcAuth`
- some code cleanup, quite a bunch of code removed and some renaming (including breaking changes, reason for new major version)

### 2.6.6

- import spring-boot 2.5.5 BOM (instead of inheriting 2.5.4 POM)

### 2.6.5

- Downgrade Java compatibility to 1.8

### 2.6.1

- spring-boot 2.5.4

### 2.6.0

- replace `KeycloakOidcIdAuthenticationConverter` with `SynchronizedJwt2OidcIdAuthenticationConverter` and complement it with `ReactiveJwt2OidcIdAuthenticationConverter`
- remove references to Keycloak from `spring-addons-oauth2` (implementations where mostly useless)

### 2.5.4

- bump Keycloak BOM to 14.0.0

### 2.5.3

- bump spring-boot to 2.5

### 2.5.1

- introduce `@JsonObjectClaim` and `@JsonArrayClaim` to configure complex private claims. Sample: `@WithMockKeycloakAuth(otherClaims = @ClaimSet(jsonObjectClaims = @JsonObjectClaim(name = "foo", value = "{\"bar\":\"bad\", \"nested\":{\"deep\":\"her\"}, \"arr\":[1,2,3]}")))` or `@WithMockOidcId(privateClaims = @JsonObjectClaim(name = "foo", value = "{\"bar\":\"bad\", \"nested\":{\"deep\":\"her\"}, \"arr\":[1,2,3]}"))`

### 2.4.1

- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) added jti and nbf (from JWT spec) to @IdTokenClaims (an ID token is a JWT)
- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) added session_state to @IdTokenClaims as per https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions
- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) rename `privateClaims` to `otherClaims` in `@WithMockKeycloakAuth`
- [issue #15](https://github.com/ch4mpy/spring-addons/issues/15) `GrantedAuthoritiesMapper` is now optional in test config. Defaulted to `NullAuthoritiesMapper`

### 2.4.0

- rename `ServletKeycloakAuthUnitTestingSupport::keycloakAuthenticationToken()` to `authentication()` to improve API fluidity (`api.with(keycloak.authentication()).get(...)`)

### 2.3.0

- implementation closer to [open ID specs](https://openid.net/specs/openid-connect-core-1_0.html): split claims into `@IdTokenClaims` and `@OidcStandardClaims`
- re-use OIDC ID annotations into `@WithMockKeycloakAuth`

### 2.2.0

- `OidcId::getName()` returns `subject` claim instead of `preferred_username`
- replace `name` with `subject` in `@WithMockOidcId`
- replace `name` from `@WithMockKeycloakAuth` with `preferedUsername` in `@WithAccessToken`
- support for private claims in `@WithMockOidcId` and `@WithMockKeycloakAuth` (claims with values of type `int`, `long`, `String` and `String[]` only)
- add missing subject claim in Keycloak access and ID tokens
- compose `@WithAccessToken` with `@WithKeycloakIDToken` instead of repeting properties (`AccessToken` extends `IDToken`)
- add advanced `@WithMockKeycloakAuth` sample usage in [`spring-addons-oauth2-test` README](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test)

### 2.1.0

- fix Keycloak typo (was wrongly spelled Keycloack at many places)
- add samples with authrities retieved from a DB instead of the JWT for both OAuthentication and JwtAuthenticationToken
- add sample involving `keycloak-spring-boot-starter` and `keycloak-spring-security-adapter`

### 2.0.0

These release is still focused on unit-testing Spring OAuth2 applications

- `@WithMockAuthentication` annotation along with `mockAuthentication()` servlet (webmvc) and reactive (webflux) flow APIs. You choose the `Authentication` type, the framework feeds the security context with a Mockito mock. This is dead simple but should cover 99% of test cases. I wonder why I didn't think of it sooner...
- Focus solely on adding to Spring `Authentication` implementations and tests tooling (no more alternatives, with an exception for `OidcId` which overlaps Spring's `OidcIdToken`)
- Split `webmvc` (servlets) and `webflux` (reactive) code in distinct libs to ease dependency management
- Re-shuffle packages and jars (less code, less jars, more expressive package names)
- WIP: Extensives samples and tests. Samples are boot apps under `src/test` to keep jars small
- Use Keycloak as authorisation-server for all resource-server samples, each of which configuring a specific `Authentication` impl

Note that I chose Keycloak because it's a feature rich, easy to setup authorisation-server.
It should not be much of an effort to migrate sample resource-servers to another one, with an exception of those using `KeycloakAuthenticationToken` as authentication impl, of course.

## Reminders for dev env setup

Cheat-sheets for me when setting up a new development environment

### GPG sigin key
``` bash
gpg --list-keys
# if key absent, then generate one with
gpg --gen-key
# publish public key to one of supported servers 
gpg --keyserver hkp://pgp.mit.edu --send-keys (replace with "pub" key)
```

### ~/.m2/settings.xml
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
