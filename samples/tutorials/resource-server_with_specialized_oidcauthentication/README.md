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
Lets first define our new `Authentication` implementation, with `proxies`:
```java
@Data
@EqualsAndHashCode(callSuper = true)
public static class MyAuthentication extends OidcAuthentication<OidcToken> {
	private static final long serialVersionUID = 6856299734098317908L;

	private final Map<String, List<String>> proxies;

	public MyAuthentication(OidcToken token, Collection<? extends GrantedAuthority> authorities, Map<String, List<String>> proxies, String bearerString) {
		super(token, authorities, bearerString);
		final Map<String, List<String>> tmp = new HashMap<>(proxies.size());
		proxies.forEach((k, v) -> tmp.put(k, Collections.unmodifiableList(v)));
		this.proxies = Collections.unmodifiableMap(tmp);
	}
}
```

### Custom method security SpEL handler
Please note the `hasProxy` method below <hich makes use of our MyAuthentication proxies:
```java
@Component
public static class MyMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, MethodInvocation invocation) {
		final var root = new MyMethodSecurityExpressionRoot(authentication);
		root.setThis(invocation.getThis());
		root.setPermissionEvaluator(getPermissionEvaluator());
		root.setTrustResolver(getTrustResolver());
		root.setRoleHierarchy(getRoleHierarchy());
		root.setDefaultRolePrefix(getDefaultRolePrefix());
		return root;
	}

	static final class MyMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

		private Object filterObject;
		private Object returnObject;
		private Object target;

		public MyMethodSecurityExpressionRoot(Authentication authentication) {
			super(authentication);
		}

		public boolean hasProxy(String subject, String permission) {
			final var auth = (MyAuthentication) this.getAuthentication();
			return subject == null || permission == null ? false : auth.getProxies().getOrDefault(subject, List.of()).contains(permission);
		}

		@Override
		public void setFilterObject(Object filterObject) {
			this.filterObject = filterObject;
		}

		@Override
		public Object getFilterObject() {
			return filterObject;
		}

		@Override
		public void setReturnObject(Object returnObject) {
			this.returnObject = returnObject;
		}

		@Override
		public Object getReturnObject() {
			return returnObject;
		}

		void setThis(Object target) {
			this.target = target;
		}

		@Override
		public Object getThis() {
			return target;
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

	public interface ProxiesConverter extends Converter<Jwt, Map<String, List<String>>> {
	}

	@SuppressWarnings("unchecked")
	@Bean
	public ProxiesConverter proxiesConverter() {
		return jwt -> {
			final var proxiesClaim = jwt.getClaims().get("proxies");
			if (proxiesClaim == null) {
				return Map.of();
			}
			return (Map<String, List<String>>) proxiesClaim;
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
com.c4-soft.springaddons.security.cors[0].allowed-origins=http://localhost,https://localhost,https://localhost:8100,https://localhost:4200
com.c4-soft.springaddons.security.permit-all=/actuator/health/readiness,/actuator/health/liveness,/v3/api-docs/**
```

## Sample `@RestController`
Note the `@PreAuthorize("hasProxy(#otherSubject, 'greet')")` on the second method, which asserts that the user has a "greet" permission for the `@PathVariable("otherSubject")` (the route is `/greet/{otherSubject}`).

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
	@PreAuthorize("hasProxy(#otherSubject, 'greet')")
	public String getGreetingOnBehalfOf(@PathVariable("otherSubject") String otherSubject, MyAuthentication auth) {
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
			final var proxies = Stream.of(annotation.proxies()).collect(Collectors.toMap(Proxy::proxiedSubject, p -> Stream.of(p.permissions()).toList()));
			return new MyAuthentication(new OidcToken(claims), super.authorities(annotation.authorities()), proxies, annotation.bearerString());
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
	void testGreet() throws Exception {
		mockMvc
				.perform(get("/greet").secure(true))
				.andExpect(status().isOk())
				.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR] and can proxy: [chose, machin]."));
	}

	@Test
	@WithMyAuth(authorities = { "NICE_GUY", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"), proxies = {
			@Proxy(onBehalfOf = "ch4mpy", can = { "greet" }) })
	void testWithProxy() throws Exception {
		mockMvc.perform(get("/greet/ch4mpy").secure(true)).andExpect(status().isOk()).andExpect(content().string("Hi ch4mpy!"));
	}

	@Test
	@WithMyAuth(authorities = { "NICE_GUY", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void testWithoutProxy() throws Exception {
		mockMvc.perform(get("/greet/ch4mpy").secure(true)).andExpect(status().isForbidden());
	}

}
```