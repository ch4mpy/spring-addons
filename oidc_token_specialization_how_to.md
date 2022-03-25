# How to specialize `OidcToken` to parse more private-claims than those holding authorities
This describes the advanced configuration for applications needing to parse more private claims than those holding authorities.
You should have gone through [this tutorial](https://github.com/ch4mpy/spring-addons/blob/master/resource-server_with_oidcauthentication_how_to.md) first

## Define `OidcToken` specialization
Lets say that our authorization-server populates a `proxies` private-claim which is a map with:
- other users subject as key
- a list of authorizations each user has provided current user with

Here is an implementation for a `DemoOidcToken` parsing such a private claim
```java
public class DemoOidcToken extends OidcToken {
	private static final long serialVersionUID = -337195865761765281L;
	private final Map<String, Proxy> proxies;

	public DemoOidcToken(Map<String, Object> claims) {
		super(claims);
		@SuppressWarnings("unchecked")
		final var claim = Optional.of((Map<String, JSONArray>) claims.get("proxies")).orElse(Map.of());
		this.proxies = new HashMap<>(claim.size());
		claim.forEach((k, v) -> proxies.put(k, new Proxy(k, v.stream().map(Object::toString).collect(Collectors.toSet()))));
	}

	public Map<String, Proxy> getProxies() {
		return Collections.unmodifiableMap(proxies);
	}

	public Proxy getProxyFor(String proxiedUserSubject) {
		return proxies.getOrDefault(proxiedUserSubject, new Proxy(proxiedUserSubject, Set.of()));
	}

	@Data
	@AllArgsConstructor
	public static class Proxy {
		private String proxiedUserSubject;
		private Set<String> authorisations = Set.of();

		public boolean allows(String authorisation) {
			return this.authorisations.contains(authorisation);
		}
	}
}
```
This would allow us to write SpEL security statements like `#authentication.token.proxies[#otherUserSubject]?.allows('DO_SOMETHING')`

## Override token converter bean
Lets provide a `SynchronizedJwt2OidcTokenConverter<OidcToken>` bean to replace default one (and return `DemoOidcToken` instead of an `OidcToken`)
```java
@Configuration
public class SecurityBeans {
	@Bean
	public SynchronizedJwt2OidcTokenConverter<OidcToken> tokenConverter() {
		return (var jwt) -> new DemoOidcToken(jwt.getClaims());
	}
}
```

## Update `@RestController` to use the specialized `OidcToken` implementation
Please note that you can use `DemoOidcToken` extended interface either in method body or spring-security SpEL
``` java
@RestController
@RequestMapping("/greet")
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping()
	@PreAuthorize("hasAuthority('NICE_GUY')")
	public String getGreeting(OidcAuthentication<DemoOidcToken> auth) {
		return String
				.format(
						"Hi %s! You are granted with: %s and have proxies for %s.",
						auth.getToken().getPreferredUsername(),
						auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")),
						auth.getToken().getProxies().keySet().stream().collect(Collectors.joining(", ", "[", "]")));
	}
}
```

## Unit-tests
### Define `@WithDemoAuth`
We need to define a test annotation for populating test security-context with an `OidcAuthentication` holding a `DemoOidcToken`.
Lets copy from `@WithMockOidcAuth`, adding proxies claim configuration:
```java
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithDemoAuth.Factory.class)
public @interface WithDemoAuth {

	@AliasFor("authorities")
	String[] value() default { "ROLE_USER" };

	@AliasFor("value")
	String[] authorities() default { "ROLE_USER" };

	OpenIdClaims claims() default @OpenIdClaims();

	String bearerString() default "machin.truc.chose";

	Proxy[] proxies() default {};

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public static final class Factory extends AbstractAnnotatedAuthenticationBuilder<WithDemoAuth, OidcAuthentication<DemoOidcToken>> {
		@Override
		public OidcAuthentication<DemoOidcToken> authentication(WithDemoAuth annotation) {
			final var claims = super.claims(annotation.claims());
			final var proxiesClaim = (Map<String, Object>) claims.getOrDefault("proxies", new HashMap<>());
			for (final var p : annotation.proxies()) {
				final var arr = new JSONArray();
				Collections.addAll(arr, p.grants());
				proxiesClaim.put(p.proxiedUserSubject(), arr);
			}
			claims.put("proxies", proxiesClaim);
			return new OidcAuthentication<>(new DemoOidcToken(claims), super.authorities(annotation.authorities()), annotation.bearerString());
		}
	}

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	public @interface Proxy {

		String proxiedUserSubject();

		String[] grants() default {};
	}
}
```

### Use test annotation
```java
@WebMvcTest
class GreetingControllerTest {

	@MockBean
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@Autowired
	MockMvc mockMvc;

	@Test
	@WithDemoAuth(authorities = { "NICE_GUY", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"), proxies = {
			@Proxy(proxiedUserSubject = "abcd", grants = { "READ" }),
			@Proxy(proxiedUserSubject = "efgh", grants = { "READ", "WRITE" }) })
	void test() throws Exception {
		mockMvc
				.perform(get("/greet").secure(true))
				.andExpect(status().isOk())
				.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR] and have proxies for [efgh, abcd]."));
	}
}
```

