# spring-security-oauth2-test-webmvc-addons

Set of tools I find useful to test Spring servlet web apps (webmvc).

```xml
	<dependencies>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-test-webmvc-addons</artifactId>
			<version>${com.c4-soft.springaddons.version}</version>
			<scope>test</scope>
		</dependency>
	</dependencies>
```

## Sample applications

I put quite a few spring-boot app samples. To keep jar small, it is under `src/test` folders but can still be run / debug from within your favorite IDE.

I recommand you clone my repo and debug the samples with a REST client like Postman, so that you can hack the config and tests.
Adapting the samples to your Keycloak instance should be just a matter of editing `application.properties`.

**Caveat** do not narrow your exploration to `keycloak` sample just beacause you are using a Keycloak authorization-server:
I run all samples against a Keycloak instance.

You should have a look at other samples too which might be simpler, not pulling Keycloak dependencies and more flexible.

Last, `*RetrievingAuthoritiesFromDatabase` samples retrieve authorities from a DB instead of extracting it from JWT claims. The key in the DB is the user "subject".
In that case, Keycloak authorisation-server is responsible for ensuring user ID only, authorities are the responsibility of the resource-server.
As a consequence, (to run only, not in unit-tests) those samples expect a database to be accessible and populated, which I can't do for you
as I can't know the "subject" claims for your test users registered in your Keycloak instance.

## `MockMvc` post-processors

I propose a few classes implementing `RequestPostProcessor` to use with `MockMvc`:

- `MockAuthenticationRequestPostProcessor` to use a Mockito mock of an `Authentication` descendent of your choice (any type implementing `Authentication`)
- `OidcIdAuthenticationRequestPostProcessor` to have `TestSecurityContext` populated with an ... `OidcIdAuthenticationToken`
- `KeycloakAuthRequestPostProcessor` to have `TestSecurityContext` populated with a ... `KeycloakAuthenticationToken`

```java
import static com.c4_soft.springaddons.security.oauth2.test.mockmvc.OidcIdAuthenticationRequestPostProcessor.mockOidcId;

@Test
public void greetCh4mpy() throws Exception {
	mockMvc.with(ch4mpy())
			.get("/greet")
			.andExpect(content().string("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
}

private OidcIdAuthenticationRequestPostProcessor ch4mpy() {
	return mockOidcId().token(oidcId -> oidcId.preferredUsername("Ch4mpy"))
			.authorities("ROLE_AUTHORIZED_PERSONNEL");
}
```

again, browse the test sources for more samples, there are quite a few there.

## `WebTestClientSupport`

A wrapper for `MockMvcSupport` providing with configurable default charset and media-type, payloads serialization using `SerializationHelper` and shortcuts for most requests.
`SerializationHelper` scans for registered `HttpMessageConverters` and then serializes payloads according to media-type and charset you specified, configured with below properties, or using defaults

Configuration properties are:

- `com.c4-soft.springaddons.test.web.default-charset` defaulted to `utf-8`
- `com.c4-soft.springaddons.test.web.default-media-type` defaulted to `application+json`

```java
mockMvc.perform(get("/greet").accept(MediaType.APPLICATION_JSON).header("Accept-Encoding", "UTF-8"))
```

becomes

```java
mockMvc.get("/greet")
```

To use it, you can for instance `@Import(MockMvcSupport.class)`, scan for components in `com.c4_soft.springaddons.security.oauth2.test.mockmvc` package, add `MockMvcSupport.class` to `@ContextConfiguration` classes, etc. (has to be instantiated by Spring for config properties to be parsed / defaulted)
