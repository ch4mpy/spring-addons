# spring-security-test addons

```xml
	<dependencies>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-test-addons</artifactId>
			<version>${com.c4-soft.springaddons.version}</version>
			<scope>test</scope>
		</dependency>
	</dependencies>
```

## Abstract

### Good reasons to use this lib instead of what I contributed to `spring-security-test`

- you need to unit test a `@Component` (that isn't a `@Controller`) with an OAuth2 security-context (or just prefer annotations over flow APIs)
- your application configures something else than `JwtAuthenticationToken` as `Authentication` implementation

### Why unit-testing security at all?

IMO, security is a major business concern.
As so, a correctly configured `SecurityContext` is a "must have" when running unit-tests and
I couldn't imagine using OAuth2 if I couldn't easily write unit-tests.

When I write "business concern", I mean my use case are generally expressed as
_"As a [user_role], when I [screen_interaction], then [expected_result]"_
and so many of it have `expected_result` look like _"should be able to ..."_, _"should see all of ... and it only"_, etc.

So spring security expressions are actually part of business needs implementations I definitely wanted to finely unit-test,
not just cover partially in integration-tests.

## Usage

With Spring 5, spring-security-test provides ways to inject any kind of `Authorization`
in the test `SecurityContext`, including OAuth2 implementations. So it is possible to do something like:

```java
mockMvc.perform(get("/greeting").with(authentication(new JwtAuthenticationToken(jwt, authorities)))
    .andExpect(...)
```

Well, cool, but, hum... building this `jwt` is cumbersome :-/
And by the way, how do I test my secured `@Component` outside of a HTTP request (so without `MockMvc` or `WebTestClient`)?

Thats where this lib jumps in: providing with annotations and helpers to build not only test `JwtAuthenticationToken`,
but also quite a few other `Authentication` implementations (and elements it contains).

With minimum steup, you will be enabled to do:

```java
@Test
@WithMockAuthentication(name = "admin", authorities = {"ROLE_USER", "ROLE_ADMIN"})
public void demoAnnotation() {
	mockMvc.perform(get("/greeting"))
	        .andExpect(content().string(is("Hello, admin! You are granted with [ROLE_USER, ROLE_ADMIN]")));
}
```

### Annotations

Annotations enable to test any kind of `@Component` when both `MockMvc`
post-processors and `WebTestClient` configurers are limited to unit-testing `@Controllers` public API.

You'll pick one of following implementations, depending on what `Authentication` implementation your application relies on:

- `@WithMockAuthentication` configures the security context with a `Mockito` mock of any `Authentication` implementation. Thes means that `@WithMockAuthentication(UsernamePasswordAuthenticationToken.class)` provides with a security-context very close to what `@WithMockUser()` does. It becomes useful for `Authentication` specialisations which do not have dedicated annotations such as `JwtAuthenticationToken`, `BearerTokenAuthenticationToken` and so on.
- `@WithMockOidcId` configures the security context with an `OidcIdAuthenticationToken`
- `@WithMockKeycloakAuth` configures the security context with a `KeycloakAuthenticationToken`

### `@WithMockAuthentication` advanced usage

If you ever need to to do extra configuration on `Authentication` mock, you might act in three steps:

- access the authentication mock with `TestSecurityContextHolder.getContext().getAuthentication()`
- (optionally) cast it to the `authType` you provided `@WithMockAuthentication` with
- tune it with regular Mockito API

```java
@Test
@WithMockAuthentication(authType = BearerTokenAuthenticationToken.class, name = "ch4mpy", authorities = {"ROLE_AUTHORIZED_PERSONNEL"})
public void test() {
	final var auth = (BearerTokenAuthenticationToken) TestSecurityContextHolder.getContext().getAuthentication();
	final var principal = mock(OAuth2AuthenticatedPrincipal.class);
	final var credentials = mock(OAuth2AccessToken.class);
	// extra configuration for principal & credentials mocks
	when(auth.getPrincipal()).thenReturn(principal);
	when(auth.getCredentials()).thenReturn(credentials);

	client.get("/greet").expectBody(String.class)
		.isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
}
```

### `@WithMockKeycloakAuth` sample usage

You might customize about any claim in Keycloak access and ID tokens.
As Keycloak `AccessToken` extends `IDToken` and annotation inheritance is not possible in Java, I used composition (reason for `idToken` property in `@WithAccessToken`).

```java
	@Test
	@WithMockKeycloakAuth(
			authorities = { "USER", "AUTHORIZED_PERSONNEL" },
			id = @IdTokenClaims(sub = "42"),
			oidc = @OidcStandardClaims(
					email = "ch4mp@c4-soft.com",
					emailVerified = true,
					nickName = "Tonton-Pirate",
					preferredUsername = "ch4mpy"),
			privateClaims = @ClaimSet(stringClaims = @StringClaim(name = "foo", value = "bar")))
	public void whenAuthenticatedWithKeycloakAuthenticationTokenThenCanGreet() throws Exception {
		api.get("/greet")
				.andExpect(status().isOk())
				.andExpect(content().string(startsWith("Hello ch4mpy! You are granted with ")))
				.andExpect(content().string(containsString("AUTHORIZED_PERSONNEL")))
				.andExpect(content().string(containsString("USER")));
	}
```
