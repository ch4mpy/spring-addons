# spring-security-test addons
I initiated this lib while contributing OAuth2 unit-test support to Spring framework. For various reasons, I keep it growing.

As I now publish this lib on maven-central, something like following Maven configuration should be enough:
``` xml
	<dependencies>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-test-oauth2-addons</artifactId>
			<version>${project.version}</version>
			<scope>test</scope>
		</dependency>
	</dependencies>
```

## Abstract

### Why using this lib instead of what I contributed to `spring-security-test`?
* you need annotations (for instance if you need to unit test a `@Service` with an OAuth2 security-context) or just prefer annotations over flow APIs.
I proposed it but Spring team was just not interested in it.
* you use introspection. Spring team showed no more interest to introspection unit test support I wrote than it did to annotations...
* you opted for `OAuth2ClaimSetAuthentication<>` I propose in `spring-security-addons` instead of `JwtAuthenticationToken`

### Why unit-testing security?
IMO, security is a major business concern, it doesn't make sense to unit-test controllers and services without security.
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
``` java
mockMvc.perform(get("/greeting").with(authentication(new JwtAuthenticationToken(jwt, authorities)))
    .andExpect(...)
``` 
Well, cool, but, hum... building this `jwt` is cumbersome :-/

Thats where this lib jumps in: it provides with helpers to build not only test `jwt`,
but also quite a few other OAuth2 `Authentication` implementations (and elements it contains).

Warning: this lib takes a different approach to `spring-security-test`. Instead of using static factories such as `mockJwt()`, I use test class parents.
Reason for this is it enables to configure test context with authorities converters mocks or real instances and use those while building authentication instances.

So, by default, authorities converters are mocked, but if your test class context is configured with an explicit converter instance,
this lib backs-off and your converter instance is used to retrieve test-case authorities.

### Test setup
From version 0.1.0, all your test class needs is, depending of the OAuth2 `Authentication` implementation your application uses, extend one of:
* `JwtClaimSetAuthenticationUnitTestsParent`
* `IntrospectionClaimSetAuthenticationUnitTestsParent`
* `JwtAuthenticationTokenUnitTestsParent`
* `OAuth2IntrospectionAuthenticationTokenUnitTestsParent`

If inheritance is not an option for you, you should be able to collaborate with one of above with little fuzz.

### Annotations
I favor annotations because it enables to test any kind of `@Component` when both `MockMvc` 
post-processors and `WebTestClient` configurers are limited to `@Controllers`.

You'll pick one of following implementations, depending on what `Authentication` implementation your application relies on:
 * `@WithMockJwt` configures the security context with a `JwtAuthenticationToken`
 * `@WithMockIntrospection` configures the security context with an `OAuth2IntrospectionAuthenticationToken`
 * `@WithMockJwtClaimSet` configures the security context with an `OAuth2ClaimSetAuthentication<WithAuthoritiesJwtClaimSet>`
 * `@WithMockIntrospectionClaimSet` configures the security context with an `OAuth2ClaimSetAuthentication<WithAuthoritiesIntrospectionClaimSet>`

Basic sample covering most use-cases:
``` java
@Test
@WithMockJwtClaimSet(name = "ch4mpy", authorities = "AUTHORIZED_PERSONEL")
public void demo() throws Exception {
    mockMvc.perform(get("/greeting"))
        .andExpect(content().string(is("Hello, ch4mpy!")));

    mockMvc.perform(get("/restricted/greeting"))
        .andExpect(content().string(is("Welcome to restricted area.")));
}
```

Configuring `Map<String, Object>` entries such as claims, headers, token-attributes, etc. with `@StringAttribute`:
``` java
    @Test
    @WithMockJwtClaimSet(claims = {
            @StringAttribute(name = JwtClaimNames.SUB, value = "ch4mpy"),
            @StringAttribute(name = "authorities", value = "AUTHORIZED_PERSONEL") })
    public void demoWithMockJwtClaims() throws Exception {
        mockMvc.perform(get("/greeting"))
            .andExpect(content().string(is("Hello, ch4mpy!")));

        mockMvc.perform(get("/restricted/greeting"))
            .andExpect(content().string(is("Welcome to restricted area.")));
    }
```

### Flow APIs

#### Sample usage with `MockMvc` request post-processor
OAuth2ClaimSetAuthentication request post-processor sample. `securityRequestPostProcessor()` is where the magic happens:
``` java
@WebMvcTest( ShowcaseController.class )
public class ShowcaseControllerTests extends JwtClaimSetAuthenticationUnitTestsParent {
    @Test
    public void demo() throws Exception {
        mockMvc.perform(get("/jwt").with(securityRequestPostProcessor()))
            .andExpect(content().string(is("{sub=user}")));

        mockMvc.perform(get("/restricted/greeting").with(securityRequestPostProcessor(claims -> claims.authorities("AUTHORIZED_PERSONEL"))))
            .andExpect(content().string(is("Welcome to restricted area.")));
    }
```

`JwtAuthenticationToken` request post-processor sample /!\ differs from what I contributed to `spring-security-test` /!\:
``` java
@WebMvcTest( ShowcaseController.class )
public class ShowcaseControllerTests extends JwtAuthenticationTokenUnitTestsParent {
	@Autowired
	MockMvc mockMvc;
	
    @Test
    public void demo() throws Exception {
        mockMvc.perform(get("/jwt").with(securityRequestPostProcessor()))
            .andExpect(content().string(is("{sub=user}")));

        mockMvc.perform(get("/restricted/greeting").with(securityRequestPostProcessor().authorities("AUTHORIZED_PERSONEL")))
            .andExpect(content().string(is("Welcome to restricted area.")));
    }
}
```

Hope you got it for "introspection" equivalents.

#### Sample usage with `WebTestClient` configurer
Sample for OAuth2ClaimSetAuthentication. Notice `securityWebTestClientConfigurer()`:
``` java
public class JwtClaimSetAuthenticationConfigurerTests extends JwtClaimSetAuthenticationUnitTestsParent {
	@Test
	public void testDefaultJwtConfigurer() {
		TestController.clientBuilder()
				.apply(securityWebTestClientConfigurer()).build()
				.get().uri("/authentication").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(String.format(
						"Authenticated as %s granted with %s. Authentication type is %s.",
						Defaults.AUTH_NAME,
						Arrays.asList(Defaults.AUTHORITIES),
						OAuth2ClaimSetAuthentication.class.getName()));
    }
    

	@Test
	public void testCustomJwtConfigurer() {
		TestController.clientBuilder()
				.apply(securityWebTestClientConfigurer(claims -> claims.subject("ch4mpy").authorities("message:read"))).build()
				.get().uri("/authentication").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(String.format(
						"Authenticated as %s granted with %s. Authentication type is %s.",
						"ch4mpy",
						"[message:read]",
						OAuth2ClaimSetAuthentication.class.getName()));
	}
    
```

As usual, let your favorite IDE auto-completion guide you to other OAuth2 `Authentication` implementations (don't forget to switch test class parent).

### Test setup for a secured `@Service`
Please refer to [MessageServiceTests](https://github.com/ch4mpy/spring-addons/blob/master/spring-security-test-oauth2-addons/src/test/java/org/springframework/security/test/context/support/MessageServiceTests.java) 
for a complete working sample.