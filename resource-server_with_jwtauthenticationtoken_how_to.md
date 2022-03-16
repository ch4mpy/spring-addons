# How to configure a Spring REST API with `JwtAuthenticationToken`
Please note that `JwtAuthenticationToken` has a rather poor interface (not exposing OpenID standard claims for instance) and that required configuration is rather cumbersome.
For a simpler configuration and richer `Authentication` implementation, please have a look at [this other tutorial](https://github.com/ch4mpy/spring-addons/blob/master/resource-server_with_oidcauthentication_how_to.md)

## Start a new project
You may start with https://start.spring.io/
Following dependencies will be needed:
- Spring Web
- OAuth2 Resource Server
- lombok

## Create web-security config
Two options:
- your services consume identities emitted by a single authorization-server: you can provide just an authentication converter with `http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(...)`
- you have one or more authorization-server(s): configure an authentication manager resolver like we'll be doing here

A few more specs for a REST API:
- enable and configure CORS
- disable CSRF
- stateless sessions
- enable anonymous
- return 401 instead of redirecting to login
```java
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	private final ServerProperties serverProperties;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// Configure an authentication manager accepting identities from several authorization-servers
		http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver()));

		// Enable anonymous
		http.anonymous();

		// Enable CORS (see corsConfigurationSource() for details)
		http.cors();

		// Disable CSRF
		http.csrf().disable();

		// Stateless sessions (state in the JWT only)
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		// Disable redirect to login (return 401)
		http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
			response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
		});

		// Force redirect to https if SSL enabled
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel().anyRequest().requiresSecure();
		} else {
			http.requiresChannel().anyRequest().requiresInsecure();
		}

		// permit anonymous access to actuator probes and Swagger-UI
		// @formatter:off
		http.authorizeRequests()
			.antMatchers("/actuator/health/readiness,/actuator/health/liveness,/v3/api-docs/**").permitAll()
			.anyRequest().authenticated();
		// @formatter:on
	}

	@Bean
	public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
		final var locations = Stream.of("https://my-resource-server.pf/auth/realms/master");
		final Map<String, AuthenticationManager> managers = locations.collect(Collectors.toMap(l -> l, l -> {
			final JwtDecoder decoder = new SupplierJwtDecoder(() -> JwtDecoders.fromIssuerLocation(l));
			final var provider = new JwtAuthenticationProvider(decoder);
			provider.setJwtAuthenticationConverter(authenticationConverter(authoritiesConverter()));
			return provider::authenticate;
		}));
		return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) managers::get);
	}

	@Bean
	public AuthenticationConverter authenticationConverter(AuthoritiesConverter authoritiesConverter) {
		return (var jwt) -> new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt));
	}

	@Bean
	public AuthoritiesConverter authoritiesConverter() {
		// @formatter:off
		return (var jwt) -> Stream.concat(
					jwt.getClaimAsStringList("realm_roles").stream(),
					jwt.getClaimAsStringList("resource_access.client1.roles").stream())
				.map(r -> String.format("ROLE_%s", r.toUpperCase()))
				.map(r -> (GrantedAuthority) new SimpleGrantedAuthority(r))
				.toList();
		// @formatter:on
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		final var source = new UrlBasedCorsConfigurationSource();
		final var configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("*"));
		configuration.setAllowedHeaders(Arrays.asList("*"));
		configuration.setExposedHeaders(Arrays.asList("*"));
		source.registerCorsConfiguration("/greet/**", configuration);
		return source;
	}

	public static interface AuthoritiesConverter extends Converter<Jwt, Collection<GrantedAuthority>> {
	}

	public static interface AuthenticationConverter extends Converter<Jwt, JwtAuthenticationToken> {
	}

}
```

Of course, there are a few values you'll want to externalize in configuration properties and inject with `@Value` or with a `@ConfigurationProperties` bean (authorization-servers URIs, CORS paths, Keycloak client names, ...)

## Sample `@RestController`
``` java
@RestController
@RequestMapping("/greet")
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping()
	@PreAuthorize("hasAuthority('NICE_GUY')")
	public String getGreeting(JwtAuthenticationToken auth) {
		return String.format(
				"Hi %s! You are granted with: %s.",
				auth.getToken().getClaimAsString("preferred_username"),
				auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")));
	}
}
```

## Unit-tests
You might use either `jwt` MockMvc request post processor from `org.springframework.security:spring-security-test` or `@WithMockJwt` from `com.c4-soft.springaddons:spring-security-oauth2-test-addons`.

Here is a sample usage for request post-processor:
```java
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest
class GreetingControllerTest {

    @MockBean
    AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

    @Autowired
    MockMvc mockMvc;

    @Test
    void test() throws Exception {
        mockMvc.perform(get("/greet").secure(true).with(jwt().jwt(jwt -> {
            jwt.claim("preferred_username", "Tonton Pirate");
        }).authorities(List.of(new SimpleGrantedAuthority("NICE_GUY"), new SimpleGrantedAuthority("AUTHOR")))))
            .andExpect(status().isOk())
            .andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR]."));
    }

}
```
Same test with `@WithMockJwt`:
```java
    @Test
    @WithMockJwtAuth(authorities = { "NICE_GUY", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
    void test() throws Exception {
        mockMvc.perform(get("/greet"))
            .andExpect(status().isOk())
            .andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR]."));
    }
```
