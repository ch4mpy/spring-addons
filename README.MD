# Spring-addons

Set of tools I find useful to work with Spring-framework.
For now it is focused on spring-security with OAuth2, but could grow.

As I write this, latest `springaddons.version` is `3.1.5` but I could forget to update before releasing, so please refer to https://repo1.maven.org/maven2/com/c4-soft/springaddons/spring-addons/ to pick latest available release of one of the following:

```xml
	<properties>
		<!-- each release is made for JDKs 1.8, 11 and 17 -->
		<springaddons.version>3.1.5-jdk1.8</springaddons.version>
	</properties>
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

## modules

### [`spring-security-oauth2-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-addons)

Currently limited to a **portable OpenID Authentication implementation**: `OidcIdAuthenticationToken`, which is intended to be used with any OpenID authorization server: Keycoak, Auth0, MS Identity Server, ...

### [`spring-security-oauth2-test-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-test-addons)

Code common to webmvc and webflux test libs. This includes annotations allowing to tests not only `@Controller` but also any other kind of `@Component` (such as `@Service`):
- `@WithMockKeycloakAuth` the most probable reason for you landing on this page
- `@WithMockOidcId` achieves about the same thing as `@WithMockKeycloakAuth`, building a mocked `OidcIdAuthenticationToken` (instead of `KeycloakAuthenticationToken`)
- `@WithMockAuthentication` to help (a bit, not as handy as the two others) inject a mocked `Authentication` of any type in test context

**You don't need any other dependency to use `@WithMockKeycloakAuth` in your tests**

### [`spring-security-oauth2-test-webflux-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-test-webflux-addons)

Builds on top of `spring-security-oauth2-test-addons`, adding:
- "fluent" API for `WebTestClient`
- some tooling around `WebTestClient`: configurable default media-type and charset, requests shortcuts

### [`spring-security-oauth2-test-webmvc-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-test-webmvc-addons)


Builds on top of `spring-security-oauth2-test-addons`, adding:
- "fluent" API for `MockMvc`
- some tooling around `MockMvc`: configurable default media-type and charset, requests shortcuts

## Sample applications

I put quite a few spring-boot app samples in [`spring-security-oauth2-test-webmvc-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-test-webmvc-addons/src/test/java/com/c4_soft/springaddons/samples/webmvc) and [`spring-security-oauth2-test-webflux-addons`](https://github.com/ch4mpy/spring-addons/tree/master/spring-security-oauth2-test-webflux-addons/src/test/java/com/c4_soft/springaddons/samples/webflux).

The reason why samples are in test sources (under `src/test` folders) is to keep jar small. It can, of course, be run / debug from within your favorite IDE.

I recommand you clone my repo and debug the samples with a REST client like Postman, so that you can hack the config and tests.
Adapting the samples to your Keycloak instance should be just a matter of editing `application.properties`.

**Caveat** do not narrow your exploration to `keycloak` sample just beacause you are using a Keycloak authorization-server:
I run all samples against a Keycloak instance.

Last, `*RetrievingAuthoritiesFromDatabase` samples retrieve authorities from a DB instead of extracting it from JWT claims. The key in the DB is the user "subject".
In that case, Keycloak authorisation-server is responsible for ensuring user ID only, authorities are the responsibility of the resource-server.
As a consequence, (to run only, not in unit-tests) those samples expect a database to be accessible and populated, which I can't do for you
as I can't know the "subject" claims for your test users registered in your Keycloak instance.

## Java version

1.8 or higher. It has been [11](https://github.com/ch4mpy/spring-addons/blob/6040991746d9dfef6bb72d871fef86c9aff3d687/pom.xml#L46) for long, but I'm payed for a project constrained to 1.8, so...

## `keycloak-spring-boot-starter` & `keycloak-spring-security-adapter` version

If using Keycloak with version >= `9.0.2` and < `11.0.0`, you need to add following bean to your conf because of a [regression](https://issues.redhat.com/browse/KEYCLOAK-14020):

```java
    @Configuration
	public class SpringBootKeycloakConfigResolver implements KeycloakConfigResolver {

		private KeycloakDeployment keycloakDeployment;

		private AdapterConfig adapterConfig;

		@Autowired
		public SpringBootKeycloakConfigResolver(AdapterConfig adapterConfig) {
			this.adapterConfig = adapterConfig;
		}

		@Override
		public KeycloakDeployment resolve(OIDCHttpFacade.Request request) {
			if (keycloakDeployment != null) {
				return keycloakDeployment;
			}

			keycloakDeployment = KeycloakDeploymentBuilder.build(adapterConfig);

			return keycloakDeployment;
		}
	}
```

From 11.0.0 on, just `@Import(KeycloakSpringBootConfigResolver.class)` with `@KeycloakConfiguration` on your `KeycloakWebSecurityConfigurerAdapter` implementation.

## Release notes

2.0 comes with a noticeable amount of breaking changes. So lets start tracking features.

### 3.1.3
- lombok with provided scope ([gh-31](https://github.com/ch4mpy/spring-addons/issues/31))

### 3.1.3
- spring-boot 2.6.1
- release with JDK version (compilation and runtime target)

### 3.1.0
- spring-boot 2.6

### 3.0.0
- in OAuth2 related test annotations all claims are now groupped under a single `claims = @OpenIdClaims(...)`
- `@WithMockJwtAuth` in addition to `@WithMockKeycloakAuth` and `@WithMockOidcAuth`
- some code cleanup quite a bunch of code removed and some renaming, including breaking changes, reson for new major version

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
