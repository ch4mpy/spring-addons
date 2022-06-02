# Spring-addons

This repo is not about `@WithMockKeycloakAuth` only. It also comes with a **vendor independent libs for spring OpenID resource-server** : `spring-security-oauth2-webmvc-addons` and `spring-security-oauth2-webflux-addons`. Similar to Keycloak spring libs, but can be used with any OIDC authorization-server (Keycloak included).

The code in this repo aims at:
- securing apps with `OidcAuthentication<OidcToken>` an `Authentication` implementation that is:
  - OpenID complient
  - richer than `JwtAuthenticationToken` (and easier to extend)
  - more portable thant `KeycloakAuthenticationToken`
- ease spring resource-servers JUnit tests
  - provide with annotations for a few `Authentication` implementations (`OidcAuthentication<OidcToken>`, `JwtAuthenticationToken` and `KeycloakAuthenticationToken`)
  - provide with tooling to ease writing new annotations for populating test security-context with OpenID related `Authentication` implementations

I initiated a serie of tiny tutorials to get you started (all work with Keycloak as authorisation-server):
- [How to configure an app with `JwtAuthenticationToken`](https://github.com/ch4mpy/spring-addons/blob/master/resource-server_with_jwtauthenticationtoken_how_to.md) (not so great because JwtAuthenticationToken has rather poor interface, but helps understand the security config this libs sets-up)
- [How to configure an app with `OidcAuthentication<OidcToken>`](https://github.com/ch4mpy/spring-addons/blob/master/resource-server_with_oidcauthentication_how_to.md) (Great! Easy configuration, fully OpenID complient Authentication)
- [How to specialize `OidcToken` to parse more private-claims than just roles](https://github.com/ch4mpy/spring-addons/blob/master/oidc_token_specialization_how_to.md) (Wow!, Can we really write such a powerfull Authentication implementation so easily?)
- [How to create Keycloak mapper to enrich private-claims](https://github.com/ch4mpy/spring-addons/blob/master/keycloak_mapper_with_rest_call_how_to.md) (advanced use-case with data retrieved from a secured OpendID resource-server)

Use artifacts with jdk11 or jdk1.8 suffix if you can't bump to JDK 17 or above.

Note that only master branch hosts the archetypes and older JDKs branches might stay behind JDK 17 one, so you'll have to check [maven central](https://repo1.maven.org/maven2/com/c4-soft/springaddons/spring-addons/) to find which version is available for the artifacts you want to pull.

As I write this, latest version is `4.3.1` but I could forget to update before releasing, so please refer to [maven central](https://repo1.maven.org/maven2/com/c4-soft/springaddons/spring-addons/) to pick latest available release of one of the following:

```xml
	<properties>
		<springaddons.version>4.3.1</springaddons.version>
	</properties>
	<dependencies>
		<!-- alternatively, you can pick *-jdk11 or *-jdk1.8 artifacts if can't use JDK 17 -->
		
		<!-- if here for @WithMockKeycloakAuth -->
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-addons-keycloak</artifactId>
			<version>${springaddons.version}</version>
			<scope>test</scope>
		</dependency>
		
		<!-- otherwise, one of the following pairs: -->
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-webflux-addons</artifactId>
			<version>${springaddons.version}</version>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-test-webflux-addons</artifactId>
			<version>${springaddons.version}</version>
			<scope>test</scope>
		</dependency>
		<!-- or -->
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-webmvc-addons</artifactId>
			<version>${springaddons.version}</version>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-test-webmvc-addons</artifactId>
			<version>${springaddons.version}</version>
			<scope>test</scope>
		</dependency>
	</dependencies>
```

## modules

### [`samples`](https://github.com/ch4mpy/spring-addons/tree/master/samples)
Provides samples for different security scenari, with **configuration and unit tests** for
- servlet or reactive apps
- spring's `JwtAuthenticationToken`, Keycloak's `KeycloakAuthenticationToken`, this repo `OidcAuthentication<OidcToken>`
- granted authorities retrieved from the token or from an external source (JPA repo in the sample but could be a web-service)
- usage of test annotations or "fluent API" (MockMvc request post-processors and WebTestClient mutators)

### [`spring-security-oauth2-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-addons) [`spring-security-oauth2-webmvc-addons`](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-security-oauth2-webmvc-addons) [`spring-security-oauth2-webflux-addons`](https://github.com/ch4mpy/spring-addons/tree/master/webflux/spring-security-oauth2-webflux-addons)

Contain:
- `OidcToken`: basically a claim-set (`Map<String, Object>`) with accessors for OpenID standard claims 
- a **portable OpenID Authentication implementation**: `OidcIdAuthentication<? extends OidcToken>`, which is intended to be used with any OpenID authorization server: Keycoak, Auth0, MS Identity Server, ...
- default (configurable) web-security configuration for RESTful APIs. Defaults (which can be configured from `configuration.propeties`) are:
  - CORS enabled to all routes (a REST API is not intended to serve UI)
  - CSRF disabled
  - anonymous enabled (but authentication required to all routes that is not included in `permit-all` property)
  - authorities mapped from `realm_access.roles` with no transformation (no prefix, no case alteration)
  - stateless sessions
  - 401 (instead of redirection to login) if user is not authenticated (or authentication is invalid)
- **new from 4.2.0** spring-boot auto-configuration for addons security-properties and security beans: if `spring-security-oauth2-webmvc-addons` or `spring-security-oauth2-webflux-addons` is on the classpath, web security-config for REST API is provided out of the box. All you have to do is define properties and enable methods security-config.

### [`spring-addons-keycloak`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-keycloak)

Contains the code depending on Keycloak Java libs.

Important note: You do **not** have to use `KeycloakAuthenticationToken` to authenticate your request against a Keycloak instance. Spring's `JwtAuthenticationToken`, this repo `OidcIdAuthentication<? extends OidcToken`, or an `Authentication` implementation of your own can do the job and would likely be more portable.

But if `@WithMockKeycloakAuth` is the only reason for you landing on this repo, then `spring-addons-keycloak` is the lib you are looking for.

### [`spring-security-oauth2-test-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-test-addons)

Code common to webmvc and webflux test libs. This includes annotations allowing to tests not only `@Controller` but also any other kind of `@Component` (such as `@Service`):
- `@WithMockJwtAuth` populates test security context with a `JwtAuthenticationToken`
- `@WithMockOidcId` populates test security context with an `OidcIdAuthentication<OidcToken>`
- `@WithMockAuthentication` populates test security context with a mocked `Authentication` of any type in test context (but this will probably need further configuration)

### [`spring-security-oauth2-test-webflux-addons`](https://github.com/ch4mpy/spring-addons/tree/master/webflux/spring-security-oauth2-test-webflux-addons)

Builds on top of `spring-security-oauth2-test-addons`, adding:
- "fluent" API for `WebTestClient`
- some tooling around `WebTestClient`: configurable default media-type and charset, requests shortcuts

### [`spring-security-oauth2-test-webmvc-addons`](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-security-oauth2-test-webmvc-addons)

Builds on top of `spring-security-oauth2-test-addons`, adding:
- "fluent" API for `MockMvc`
- some tooling around `MockMvc`: configurable default media-type and charset, requests shortcuts

### [`spring-webmvc-archetype-multimodule`](https://github.com/ch4mpy/spring-addons/tree/master/archetypes/spring-webmvc-archetype-multimodule)
An archetype to bootstrap a maven multi-module project focused on REST micro-services:
- Servlet @RestController
- OpenID security
- default conf providing with enabled CORS, disabled CSRF, stateless sessions, 401 instead of redirect to login, ...
- Spring exception-handling
- spring-native for smaller / faster booted services
- bootstraped JPA and unit tests
- micro-services ready (just clone "endpoints" module)

### [`spring-webmvc-archetype-singlemodule`](https://github.com/ch4mpy/spring-addons/tree/master/archetypes/spring-webmvc-archetype-singlemodule)
Same as `spring-webmvc-archetype-multimodule` with simple structure (all endpoints in a single spring-boot app)

### [`spring-webflux-archetype-singlemodule`](https://github.com/ch4mpy/spring-addons/tree/master/archetypes/spring-webflux-archetype-singlemodule)
Quite like webmvc archetype but fully reactive:
- Reactive @RestController
- OpenID security
- default conf providing with enabled CORS, disabled CSRF, stateless sessions, 401 instead of redirect to login, ...
- Spring exception-handling
- spring-native for smaller / faster booted services
- bootstraped **R2DBC** (no ORM) and unit tests
- micro-services ready (just clone "endpoints" module)

### [`spring-webflux-archetype-singlemodule`](https://github.com/ch4mpy/spring-addons/tree/master/archetypes/spring-webflux-archetype-singlemodule)
Same as `spring-webflux-archetype-multimodule` with simple structure (all endpoints in a single spring-boot app)

## Sample applications

I put quite a few spring-boot app samples in [`spring-security-oauth2-test-webmvc-addons`](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-security-oauth2-test-webmvc-addons/src/test/java/com/c4_soft/springaddons/samples/webmvc) and [`spring-security-oauth2-test-webflux-addons`](https://github.com/ch4mpy/spring-addons/tree/master/weblux/spring-security-oauth2-test-webflux-addons/src/test/java/com/c4_soft/springaddons/samples/webflux).

The reason why samples are in test sources (under `src/test` folders) is to keep jar small. It can, of course, be run / debug from within your favorite IDE.

I recommand you clone my repo and debug the samples with a REST client like Postman, so that you can hack the config and tests.
Adapting the samples to your Keycloak instance should be just a matter of editing `application.properties`.

**Caveat** do not narrow your exploration to `keycloak` sample just beacause you are using a Keycloak authorization-server:
I run all samples against a Keycloak instance.

Last, [webmvc-jwtauthenticationtoken-jpa-authorities](https://github.com/ch4mpy/spring-addons/tree/master/samples/webmvc-jwtauthenticationtoken-jpa-authorities) retrieve authorities from a DB instead of extracting it from JWT claims. The key in the DB is the user "subject".
In that case, Keycloak authorisation-server is responsible for ensuring user ID only, authorities are the responsibility of the resource-server.
As a consequence, (to run only, not in unit-tests) those samples expect a database to be accessible and populated, which I can't do for you
as I can't know the "subject" claims for your test users registered in your Keycloak instance.

## Java version

Main target is JDK 17. `jdk1.8` and `jdk11` branches will be maintained at least until spring-boot 3 is released.

## Release notes

2.0 comes with a noticeable amount of breaking changes. So lets start tracking features.

### 4.3.0
- [gh-50](https://github.com/ch4mpy/spring-addons/issues/50): One entry per authorization-server for authorities mapping (see samples `application.properties` files for new configuration structure).
- [gh-51](https://github.com/ch4mpy/spring-addons/issues/51): Group archetypes, webmvc and webflux modules.

### 4.2.1
- [gh-49](https://github.com/ch4mpy/spring-addons/issues/49): Samples in dedicated modules. All samples are moved from libs tests to [`samples`](https://github.com/ch4mpy/spring-addons/tree/master/samples) module, with one sub-module per sample.

### 4.2.0
Cleanup and prepare for spring-boot 3:
- [gh-46](https://github.com/ch4mpy/spring-addons/issues/46): split webmvc & webflux content from `spring-security-oauth2-addons` 
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
- Add [spring-webmvc-archetype-multimodule](https://github.com/ch4mpy/spring-addons/blob/master/spring-webmvc-archetype-multimodule) to boostrap native-ready Spring REST API with webmvc, JPA, OpenAPI and OpenID security.

### 3.1.13
- Add a [sample](https://github.com/ch4mpy/spring-addons/blob/master/custom-oidc-authentication-impl.MD) with `OidcToken` specialisation (parse private claims in addition to authorities).

### 3.1.12
- Improve `OidcReactiveApiSecurityConfig` and `OidcServletApiSecurityConfig` usability: ease security beans replacement (including authorities and authentication converter for use cases where OidcAuthentication is not enough)

### 3.1.11
- Rename `SecurityProperties` to less conflicting `SpringAddonsSecurityProperties`

### 3.1.10
- Turn `AbstractOidc...ApiSecurityConfig` into `Oidc...ApiSecurityConfig` with default authorities mapper being keycloak or Auth0 depending on `com.c4-soft.springaddons.security.keycloak.client-id` being set or not
- More CORS and authorities mapping configuration in `SecurityProperties`

### 3.1.8
- Fix missing JTI claim mapping from `@OpenIdClaims` ([gh-35](https://github.com/ch4mpy/spring-addons/issues/35)).

### 3.1.7
- Add `AbstractOidcReactiveApiSecurityConfig` to `spring-security-oauth2-addons`. It provides with reasonable default WebSecurityConfig for a reactive (weblux) based API secured with OidcAuthentication.

### 3.1.6
- Add `AbstractOidcServletApiSecurityConfig` to `spring-security-oauth2-addons`. It provides with reasonable default WebSecurityConfig for a servlet based API secured with OidcAuthentication.

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
- remove references to Keycloak from `spring-security-oauth2-addons` (implementations where mostly useless)

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
- add advanced `@WithMockKeycloakAuth` sample usage in [`spring-security-oauth2-test-addons` README](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-test-addons)

### 2.1.0

- fix Keycloak typo (was wrongly spelled Keycloack at many places)
- add samples with authrities retieved from a DB instead of the JWT for both OidcIdAuthentication and JwtAuthenticationToken
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
