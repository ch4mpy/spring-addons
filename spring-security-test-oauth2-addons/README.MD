# spring-security-test addons
I initiated this lib while contributing OAuth2 unit-test support to Spring framework. For various reasons, I keep it growing (and diverge).

As I now publish this lib on maven-central, something like following Maven configuration should be enough (remember to define `com.c4-soft.springaddons.version` property):
``` xml
	<dependencies>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-test-oauth2-addons</artifactId>
			<version>${com.c4-soft.springaddons.version}</version>
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

### API stability and release plan
I introduced a lot of breaking changes between `0.0.1-SNAPSHOT` and `1.0.0.M1`.
As I started to use this lib in other projects, I'm confident it is usable enough like it is and will significantly slow down commits.

Further versions will follow `spring-boot 2.0` pace. So, next milestone end of August after boot `2.0.0.M5` is out (and I reach French Polynesia)
and a release close to my birthday, according to Spring road-map.

## Usage
With Spring 5, spring-security-test provides ways to inject any kind of `Authorization` 
in the test `SecurityContext`, including OAuth2 implementations. So it is possible to do something like:
``` java
mockMvc.perform(get("/greeting").with(authentication(new JwtAuthenticationToken(jwt, authorities)))
    .andExpect(...)
``` 
Well, cool, but, hum... building this `jwt` is cumbersome :-/

Thats where this lib jumps in: providing with helpers to build not only test `jwt`,
but also quite a few other OAuth2 `Authentication` implementations (and elements it contains).

With minimum steup, you will be enabled to do:
``` java
@Test
@WithMockJwt(name = admin, authorities = {"ROLE_USER", "ROLE_ADMIN"})
public void demoAnnotation() {
	mockMvc.perform(get("/greeting"))
	        .andExpect(content().string(is("Hello, admin!")));
}

@Test
public void demoFlowApi() {
	admin().get("/greeting")
	    .andExpect(content().string(is("Hello, admin!")))
}

private MockMvcSupport admin() {
	return mockMvc().with(authentication()
		.name("admin")
		.authorities("ROLE_USER", "ROLE_ADMIN"));
}
```

**Warning:** this lib takes a different approach than `spring-security-test`. Instead of using static factories such as `mockJwt()`, I use test class parents.
Two reasons for this:
* get authorities converter from test context or mock it if absent (default and most common case, just define a `Converter` `@Bean` if you wish to replace mock)
* provide with some tooling at parent level (expose MockMvc or WebTestClient supports and OAuht2 `Authentication` factories)

### Test setup
All your test class needs is, depending of the OAuth2 `Authentication` implementation your application uses, extend one of:
* `ServletJwtAuthenticationTokenUnitTestsParent`
* `ServletOAuth2IntrospectionAuthenticationTokenUnitTestsParent`
* `ServletJwtClaimSetAuthenticationUnitTestsParent`
* `ServletIntrospectionClaimSetAuthenticationUnitTestsParent`
* `ReatctiveJwtAuthenticationTokenUnitTestsParent`
* `ReatctiveOAuth2IntrospectionAuthenticationTokenUnitTestsParent`
* `ReatctiveJwtClaimSetAuthenticationUnitTestsParent`
* `ReatctiveIntrospectionClaimSetAuthenticationUnitTestsParent`

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
    @WithMockJwtClaimSet(
    	name = "ch4mpy",
    	authorities = "AUTHORIZED_PERSONEL",
		claims = { @StringAttribute(name = "private-claim", value = "important-value") })
    public void demoWithMockJwtClaims() throws Exception {
        mockMvc.perform(get("/greeting"))
            .andExpect(content().string(is("Hello, ch4mpy!")));

        mockMvc.perform(get("/restricted/greeting"))
            .andExpect(content().string(is("Welcome to restricted area.")));
    }
```

### Flow APIs

#### Sample usage with `MockMvc` request post-processor

Test parents also provide with `MockMvc` or `WebTestClient` wrappers that quite simplify basic REST requests.

OAuth2ClaimSetAuthentication request post-processor sample. `authentication()` is where the magic happens:

`JwtAuthenticationToken` request post-processor sample **/!\ syntax is quite different from what I contributed to `spring-security-test` /!\**:
``` java
@WebMvcTest( ShowcaseController.class )
public class ShowcaseControllerTests extends ServletJwtAuthenticationTokenUnitTestsParent {
    @Test
    public void demo() throws Exception {
        mockMvc().with(authentication()).get("/jwt")
            .andExpect(content().string(is("{sub=user}")));

        mockMvc().with(authentication().authorities("AUTHORIZED_PERSONEL")).get("/restricted/greeting")
            .andExpect(content().string(is("Welcome to restricted area.")));
    }
}
```

The API is the same for all `Authentication` implementations. All you need to do is adapt the unit-test parent class.

#### Sample usage with `WebTestClient` configurer

Pretty much the same as for servlets. Just:
* provide parent constructor with controller(s) to bind `WebTestClient` to
* change `mockMvc()` to `webTestClient()` 

``` java
public class JwtClaimSetAuthenticationConfigurerTests extends ReactiveJwtClaimSetAuthenticationUnitTestsParent {

	public JwtClaimSetAuthenticationConfigurerTests() {
		super(new TestController());
	}
	
	@Test
	public void testDefaultJwtConfigurer() {
		webTestClient().with(authentication()).get("/authentication")
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(String.format(
						"Authenticated as %s granted with %s. Authentication type is %s.",
						Defaults.AUTH_NAME,
						Arrays.asList(Defaults.AUTHORITIES),
						OAuth2ClaimSetAuthentication.class.getName()));
    }
    

	@Test
	public void testCustomJwtConfigurer() {
		ch4mpy().get("/authentication")
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(String.format(
						"Authenticated as %s granted with %s. Authentication type is %s.",
						"ch4mpy",
						"[message:read]",
						OAuth2ClaimSetAuthentication.class.getName()));
	}
	
	private WebTestClientSupport ch4mpy() {
		return webTestClient().with(authentication().name("ch4mpy").authorities("message:read"));
	}
    
```

### Test setup for a secured `@Service`
Please refer to [MessageServiceTests](https://github.com/ch4mpy/spring-addons/blob/master/spring-security-test-oauth2-addons/src/test/java/org/springframework/security/test/context/support/MessageServiceTests.java) 
for a complete working sample.