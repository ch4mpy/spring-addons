# Spring-addons

Set of tools I find useful to work with Spring-framework.
For now it is focused on spring-security with OAuth2, but could grow.

Pick one of the following (remember to define `com.c4-soft.springaddons.version` property):

```xml
	<dependencies>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-addons</artifactId>
			<version>${springaddons.version}</version>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-test-addons</artifactId>
			<version>${springaddons.version}</version>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-test-webflux-addons</artifactId>
			<version>${springaddons.version}</version>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-test-webmvc-addons</artifactId>
			<version>${springaddons.version}</version>
			<scope>test</scope>
		</dependency>
	</dependencies>
```

## Release notes

2.0 comes with a noticeable amount of breaking changes. So lets start tracking features.

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
- add samples with authrities retieved from a DB instead of the JWT for both OidcIdAuthenticationToken and JwtAuthenticationToken
- add sample involving `keycloak-spring-boot-starter` and `keycloak-spring-security-adapter`

### 2.0.0

These release is still focused on unit-testing Spring OAuth2 applications

- `@WithMockAuthentication` annotation along with `mockAuthentication()` servlet (webmvc) and reactive (webflux) flow APIs. You choose the `Authentication` type, the framework feeds the security context with a Mockito mock. This is dead simple but should cover 99% of test cases. I wonder why I didn't think of it sooner...
- Focus solely on adding to Spring `Authentication` implementations and tests tooling (no more alternatives, with an exception for `OidcId` which overlaps Spring's `OidcIdToken`)
- Split `webmvc` (servlets) and `webflux` (reactive) code in distinct libs to ease dependency management
- Re-shuffle packages and jars (less code, less jars, more expressive package names)
- WIP: Extensives samples and tests. Samples are boot apps under `src/test` to keep jars small
- Use Keycloak as authorisation-server for all resource-server samples, each of which configuring a specific `Authentication` impl

Note that I chose Keycloak because it's a feature reach, easy to setup authorisation-server.
It should not be much of an effort to migrate sample resource-servers to another one, with an exception of those using `KeycloakAuthenticationToken` as authentication impl, of course.

## modules

### [`spring-security-oauth2-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-addons)

Some extensions to Spring OAuth2 that could be of use at runtime (not solely tests) such as:

- new `Authentication` implementations (`OidcIdAuthenticationToken` for instance)
- builders for `Jwt`, `BearerTokenAuthentication`, ...
- base classes for Keycloak authentication configuration

### [`spring-security-oauth2-test-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-test-addons)

Code common to webmvc and webflux test libs. This includes annotations, very useful as it allows to tests not only `@Controller` but also any other kind of `@Component` (such as `@Service`): `@WithMockAuthentication`, `@WithMockKeycloakAuth` and `@WithMockOidcId`

### [`spring-security-oauth2-test-webflux-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-test-webflux-addons)

Focus on reactive tests with

- "fluent" API for `WebTestClient`
- some tooling around `WebTestClient`: configurable default media-type and charset, requests shortcuts

### [`spring-security-oauth2-test-webmvc-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-test-webmvc-addons)

Focus on servlet tests with

- "fluent" API for `MockMvc`
- some tooling around `MockMvc`: configurable default media-type and charset, requests shortcuts

## Sample applications

I put quite a few spring-boot app samples in relevant modules. To keep jar small, it is under `src/test` folders but can still be run / debug from within your favorite IDE.

I recommand you clone my repo and debug the samples with a REST client like Postman, so that you can hack the config and tests.
Adapting the samples to your Keycloak instance should be just a matter of editing `application.properties`.

**Caveat** do not narrow your exploration to `keycloak` sample just beacause you are using a Keycloak authorization-server:
I run all samples against a Keycloak instance.

Last, `*RetrievingAuthoritiesFromDatabase` samples retrieve authorities from a DB instead of extracting it from JWT claims. The key in the DB is the user "subject".
In that case, Keycloak authorisation-server is responsible for ensuring user ID only, authorities are the responsibility of the resource-server.
As a consequence, (to run only, not in unit-tests) those samples expect a database to be accessible and populated, which I can't do for you
as I can't know the "subject" claims for your test users registered in your Keycloak instance.

## Java version

[11 or higher](https://github.com/ch4mpy/spring-addons/blob/6040991746d9dfef6bb72d871fef86c9aff3d687/pom.xml#L46). I've been asked to port this lib to Java 8. I won't. Java 8 was release in early 2014, more than 6 years ago, langage and JDK have improved and I use some of recent collections and stream APIs.

## `keycloak-spring-boot-starter` & `keycloak-spring-security-adapter` version

Because of a [regression](https://issues.redhat.com/browse/KEYCLOAK-14020) from `9.0.2` to `12.0.0`, you'll have to implement a work-around as shown in [KeycloakSpringBootSampleApp](https://github.com/ch4mpy/spring-addons/blob/master/spring-security-oauth2-test-webmvc-addons/src/test/java/com/c4_soft/springaddons/samples/webmvc/keycloak/KeycloakSpringBootSampleApp.java).

An other option is to drop Keycloak libs for Spring resource-servers and configure something else than a `KeycloakAuthenticationToken` in your security context as demonstrated for instance in [OidcIdServletAppWithJwtEmbeddedAuthorities](https://github.com/ch4mpy/spring-addons/blob/master/spring-security-oauth2-test-webmvc-addons/src/test/java/com/c4_soft/springaddons/samples/webmvc/oidcid/OidcIdServletAppWithJwtEmbeddedAuthorities.java) or [OidcIdServletAppRetrievingAuthoritiesFromDatabase](https://github.com/ch4mpy/spring-addons/blob/master/spring-security-oauth2-test-webmvc-addons/src/test/java/com/c4_soft/springaddons/samples/webmvc/oidcid/OidcIdServletAppRetrievingAuthoritiesFromDatabase.java).
