# How to extend `OidcAuthentication<OidcToken>`
Lets says that we have business requirements where security is not only role based.

Lets assume that the authorization server also provides us with a `proxies` claim that contains a map of permissions per user subject (what current user was granted to do on behalf of some other users).

This tutorial will demo
- how to extend `OidcAuthentication<OidcToken>` to hold those proxies in addition to authorities
- how to extend security SpEL to easily evaluate proxies granted to authenticated users

## Start a new project
We'll start with https://start.spring.io/
Following dependencies will be needed:
- lombok

Then add dependencies to spring-addons:
```xml
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-config</artifactId>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-webmvc-addons</artifactId>
			<version>4.3.2</version>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-test-webmvc-addons</artifactId>
			<version>4.3.2</version>
			<scope>test</scope>
		</dependency>
```

An other option would be to use one of `com.c4-soft.springaddons` archetypes (for instance `spring-webmvc-archetype-singlemodule` or `spring-webflux-archetype-singlemodule`)

## Web-security config

### MyAuthentication
Lets first define what a `Proxy` is and our new `Authentication` implementation, with `proxies`:
```java
	@Data
	public static class Proxy {
		private final String proxiedSubject;
		private final String tenantSubject;
		private final Set<String> permissions;

		public Proxy(String proxiedSubject, String tenantSubject, Collection<String> permissions) {
			this.proxiedSubject = proxiedSubject;
			this.tenantSubject = tenantSubject;
			this.permissions = Collections.unmodifiableSet(new HashSet<>(permissions));
		}

		public boolean can(String permission) {
			return permissions.contains(permission);
		}
	}

	@Data
	@EqualsAndHashCode(callSuper = true)
	public static class MyAuthentication extends OidcAuthentication<OidcToken> {
		private static final long serialVersionUID = 6856299734098317908L;

		private final Map<String, Proxy> proxies;

		public MyAuthentication(OidcToken token, Collection<? extends GrantedAuthority> authorities, Map<String, List<String>> proxies, String bearerString) {
			super(token, authorities, bearerString);
			this.proxies =
					Collections
							.unmodifiableMap(
									proxies
											.entrySet()
											.stream()
											.collect(Collectors.toMap(Map.Entry::getKey, e -> new Proxy(e.getKey(), token.getSubject(), e.getValue()))));
		}

		public Proxy getProxyFor(String proxiedUserSubject) {
			return this.proxies.getOrDefault(proxiedUserSubject, new Proxy(proxiedUserSubject, getToken().getSubject(), List.of()));
		}
	}
```

### Custom method security SpEL handler
```java
	@Component
	public static class MyMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

		@Override
		protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, MethodInvocation invocation) {
			final var root = new MyMethodSecurityExpressionRoot();
			root.setThis(invocation.getThis());
			root.setPermissionEvaluator(getPermissionEvaluator());
			root.setTrustResolver(getTrustResolver());
			root.setRoleHierarchy(getRoleHierarchy());
			root.setDefaultRolePrefix(getDefaultRolePrefix());
			return root;
		}

		static final class MyMethodSecurityExpressionRoot extends MethodSecurityExpressionRoot<MyAuthentication> {

			public MyMethodSecurityExpressionRoot() {
				super(MyAuthentication.class);
			}

			public Proxy onBehalfOf(String proxiedUserSubject) {
				return getAuth().getProxyFor(proxiedUserSubject);
			}

			public boolean isNice() {
				return hasAnyAuthority("ROLE_NICE_GUY", "SUPER_COOL");
			}
		}
	}
```

### Security @Beans
We'll rely on `spring-security-oauth2-webmvc-addons` `@AutoConfiguration` and add 
- a converter from Jwt to proxies
- a converter from Jwt to `MyAuthentication` (using the new proxies converter and existing token and authorities converters)
See [`ServletSecurityBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-security-oauth2-webmvc-addons/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/ServletSecurityBeans.java) for provided `@Autoconfiguration`
```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

	public interface ProxiesConverter extends Converter<Jwt, Map<String, Proxy>> {
	}

	@Bean
	public ProxiesConverter proxiesConverter() {
		return jwt -> {
			@SuppressWarnings("unchecked")
			final var proxiesClaim = (Map<String, List<String>>) jwt.getClaims().get("proxies");
			if (proxiesClaim == null) {
				return Map.of();
			}
			return proxiesClaim.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> new Proxy(e.getKey(), jwt.getSubject(), e.getValue())));
		};
	}

	@Bean
	public SynchronizedJwt2AuthenticationConverter<MyAuthentication> authenticationConverter(
			SynchronizedJwt2OidcTokenConverter<OidcToken> tokenConverter,
			JwtGrantedAuthoritiesConverter authoritiesConverter,
			ProxiesConverter proxiesConverter) {
		return jwt -> new MyAuthentication(tokenConverter.convert(jwt), authoritiesConverter.convert(jwt), proxiesConverter.convert(jwt), jwt.getTokenValue());
	}
}
```
### `application.properties`:
```
com.c4-soft.springaddons.security.token-issuers[0].location=http://localhost:9443/auth/realms/master
com.c4-soft.springaddons.security.token-issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons.roles
com.c4-soft.springaddons.security.cors[0].path=/greet/**
com.c4-soft.springaddons.security.cors[0].allowed-origins=https://localhost:8100,https://localhost:4200
com.c4-soft.springaddons.security.permit-all=/actuator/health/readiness,/actuator/health/liveness,/v3/api-docs/**
```

## Sample `@RestController`
Note the `@PreAuthorize("isNice() or onBehalfOf(#otherSubject).can('greet')")` on the second method, which asserts that the user has either
- one of "nice" authorities
- permission to "greet" on behalf of `@PathVariable("otherSubject")` (the route is `/greet/{otherSubject}`)

It comes from the custom method-security expression handler we configured earlier.
``` java
@RestController
@RequestMapping("/greet")
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping()
	@PreAuthorize("hasAuthority('NICE_GUY')")
	public String getGreeting(MyAuthentication auth) {
		return String
				.format(
						"Hi %s! You are granted with: %s and can proxy: %s.",
						auth.getToken().getPreferredUsername(),
						auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")),
						auth.getProxies().keySet().stream().collect(Collectors.joining(", ", "[", "]")));
	}

	@GetMapping("/{otherSubject}")
	@PreAuthorize("isNice() or onBehalfOf(#otherSubject).can('greet')")
	public String getGreetingFor(@PathVariable("otherSubject") String otherSubject) {
		return String.format("Hi %s!", otherSubject);
	}
}
```

## Unit-tests

### @WithMyAuth
`@WithOidcAuth` populates test security-context with an instance of `OicAuthentication<OidcToken>`.
Let's create a `@WithMyAuth` annotation to inject an instance of `MyAuthentication` instead (with configurable proxies)
```java
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMyAuth.MyAuthenticationFactory.class)
public @interface WithMyAuth {

	@AliasFor("authorities")
	String[] value() default { "ROLE_USER" };

	@AliasFor("value")
	String[] authorities() default { "ROLE_USER" };

	OpenIdClaims claims() default @OpenIdClaims();

	Proxy[] proxies() default {};

	String bearerString() default "machin.truc.chose";

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	public static @interface Proxy {
		String onBehalfOf();

		String[] can() default {};
	}

	public static final class MyAuthenticationFactory extends AbstractAnnotatedAuthenticationBuilder<WithMyAuth, MyAuthentication> {
		@Override
		public MyAuthentication authentication(WithMyAuth annotation) {
			final var claims = super.claims(annotation.claims());
			final var token = new OidcToken(claims);
			final var proxies =
					Stream
							.of(annotation.proxies())
							.collect(
									Collectors
											.toMap(
													Proxy::onBehalfOf,
													p -> new com.c4soft.springaddons.tutorials.WebSecurityConfig.Proxy(
															p.onBehalfOf(),
															token.getSubject(),
															Stream.of(p.can()).toList())));
			return new MyAuthentication(token, super.authorities(annotation.authorities()), proxies, annotation.bearerString());
		}
	}
}
```

### Controller test
```java
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AutoConfigureSecurityAddons;
import com.c4soft.springaddons.tutorials.WithMyAuth.Proxy;

@WebMvcTest(GreetingController.class)
@AutoConfigureSecurityAddons
@Import(WebSecurityConfig.class)
class GreetingControllerTest {

	@Autowired
	MockMvc mockMvc;

	@Test
	@WithMyAuth(authorities = { "NICE_GUY", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"), proxies = {
			@Proxy(onBehalfOf = "machin", can = { "truc", "bidule" }),
			@Proxy(onBehalfOf = "chose") })
	void whenNiceGuyThenCanBeGreeted() throws Exception {
		mockMvc
				.perform(get("/greet").secure(true))
				.andExpect(status().isOk())
				.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR] and can proxy: [chose, machin]."));
	}

	@Test
	@WithMyAuth(authorities = { "AUTHOR" })
	void whenNotNiceGuyThenForbiddenToBeGreeted() throws Exception {
		mockMvc.perform(get("/greet").secure(true)).andExpect(status().isForbidden());
	}

	// @formatter:off
	@Test
	@WithMyAuth(
			authorities = { "AUTHOR" },
			claims = @OpenIdClaims(sub = "greeter", preferredUsername = "Tonton Pirate"),
			proxies = { @Proxy(onBehalfOf = "greeted", can = { "greet" }) })
	// @formatter:on
	void whenNotNiceWithProxyThenCanGreetFor() throws Exception {
		mockMvc.perform(get("/greet/greeted").secure(true)).andExpect(status().isOk()).andExpect(content().string("Hi greeted!"));
	}

	// @formatter:off
	@Test
	@WithMyAuth(
			authorities = { "AUTHOR", "ROLE_NICE_GUY" },
			claims = @OpenIdClaims(sub = "greeter", preferredUsername = "Tonton Pirate"))
	// @formatter:on
	void whenNiceWithoutThenCanGreetFor() throws Exception {
		mockMvc.perform(get("/greet/greeted").secure(true)).andExpect(status().isOk()).andExpect(content().string("Hi greeted!"));
	}

	// @formatter:off
	@Test
	@WithMyAuth(
			authorities = { "AUTHOR" },
			claims = @OpenIdClaims(sub = "greeter", preferredUsername = "Tonton Pirate"),
			proxies = { @Proxy(onBehalfOf = "ch4mpy", can = { "greet" }) })
	// @formatter:on
	void whenNotNiceWithoutThenForbiddenToGreetFor() throws Exception {
		mockMvc.perform(get("/greet/greeted").secure(true)).andExpect(status().isForbidden());
	}

}
```