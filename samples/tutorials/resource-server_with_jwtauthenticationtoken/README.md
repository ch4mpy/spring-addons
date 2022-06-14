# How to configure a Spring REST API with `JwtAuthenticationToken` for a RESTful API

We'll build web security configuration from ground up and then greatly simplify it by using [`spring-security-oauth2-webmvc-addons`](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-security-oauth2-webmvc-addons).

Please note that `JwtAuthenticationToken` has a rather poor interface (not exposing OpenID standard claims for instance). For richer `Authentication` implementation, please have a look at [this other tutorial](https://github.com/ch4mpy/spring-addons/blob/master/resource-server_with_oidcauthentication_how_to.md).

## Start a new project
You may start with https://start.spring.io/
Following dependencies will be needed:
- Spring Web
- OAuth2 Resource Server
- Spring Boot Actuator
- lombok

We'll also need 
- `org.springframework.security`:`spring-security-test` with `test` scope
- `org.springdoc`:`springdoc-openapi-security`:`1.6.6`
- `org.springdoc`:`springdoc-openapi-ui`:`1.6.6`

## Create web-security config
A few specs for a REST API web security config:
- enable and configure CORS
- disable CSRF
- stateless sessions
- enable anonymous
- return 401 instead of redirecting to login
- enable `@PreAuthorize()`

Let's do so the spring-boot 3 way (**not** extend `WebSecurityConfigurerAdapter`)
```java
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {
	@Bean
	public
			SecurityFilterChain
			filterChain(HttpSecurity http, Converter<Jwt, ? extends AbstractAuthenticationToken> authenticationConverter, ServerProperties serverProperties)
					throws Exception {

		// Enable OIDC
		http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter);

		// Enable anonymous
		http.anonymous();

		// Enable and configure CORS
		http.cors().configurationSource(corsConfigurationSource());

		// Disable CSRF
		http.csrf().disable();

		// Stateless session (client state in JWT token only)
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		// Return 401 instead of redirect to login page
		http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
			response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
			response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
		});

		// If SSL enabled, disable http (https only)
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel().anyRequest().requiresSecure();
		} else {
			http.requiresChannel().anyRequest().requiresInsecure();
		}

		// Route security: authenticated to all routes but actuator and Swagger-UI
		// @formatter:off
		http.authorizeRequests()
				.antMatchers("/actuator/health/readiness", "/actuator/health/liveness", "/v3/api-docs/**").permitAll()
				.anyRequest().authenticated();
		// @formatter:on

		return http.build();
	}

	public interface Jw2tAuthoritiesConverter extends Converter<Jwt, Collection<? extends GrantedAuthority>> {
	}

	public interface Jwt2AuthenticationConverter extends Converter<Jwt, JwtAuthenticationToken> {
	}

	@Bean
	public Jwt2AuthenticationConverter authenticationConverter(Jw2tAuthoritiesConverter authoritiesConverter) {
		return jwt -> new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt));
	}

	@SuppressWarnings("unchecked")
	@Bean
	public Jw2tAuthoritiesConverter authoritiesConverter() {
		// This is a converter for roles as embedded in the JWT by a Keycloak server
		// Roles are taken from both realm_access.roles & resource_access.{client}.roles
		return jwt -> {
			final var realmAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("realm_access", Map.of());
			final var realmRoles = (Collection<String>) realmAccess.getOrDefault("roles", List.of());

			final var resourceAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("resource_access", Map.of());
			// We assume here you have a "spring-addons" client configure in your Keycloak realm
			final var clientAccess = (Map<String, Object>) resourceAccess.getOrDefault("spring-addons", Map.of());
			final var clientRoles = (Collection<String>) clientAccess.getOrDefault("roles", List.of());

			return Stream.concat(realmRoles.stream(), clientRoles.stream()).map(SimpleGrantedAuthority::new).toList();
		};
	}

	private CorsConfigurationSource corsConfigurationSource() {
		// Very permissive CORS config...
		final var configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*"));
		configuration.setAllowedMethods(Arrays.asList("*"));
		configuration.setAllowedHeaders(Arrays.asList("*"));
		configuration.setExposedHeaders(Arrays.asList("*"));

		// Limited to API routes (neither actuator nor Swagger-UI)
		final var source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/greet/**", configuration);

		return source;
	}
}
```

## Sample `@RestController`
``` java
@RestController
@RequestMapping("/greet")
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping()
	@PreAuthorize("hasAuthority('NICE_GUY')")
	public String getGreeting(JwtAuthenticationToken auth) {
		return String
				.format(
						"Hi %s! You are granted with: %s.",
						auth.getToken().getClaimAsString(StandardClaimNames.PREFERRED_USERNAME),
						auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")));
	}
}
```

## application.properties
For a Keycloak listening on port 9443 on localhost:
```
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://localhost:9443/auth/realms/master
```

## Unit-tests
You might use either `jwt` MockMvc request post processor from `org.springframework.security:spring-security-test` or `@WithMockJwt` from `com.c4-soft.springaddons:spring-security-oauth2-test-addons`.

Here is a sample usage for request post-processor:
```java
package com.c4soft.springaddons.tutorials.resourceserver_with_jwtauthenticationtoken;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
	void testWithPostProcessor() throws Exception {
		mockMvc.perform(get("/greet").secure(true).with(jwt().jwt(jwt -> {
			jwt.claim("preferred_username", "Tonton Pirate");
		}).authorities(List.of(new SimpleGrantedAuthority("NICE_GUY"), new SimpleGrantedAuthority("AUTHOR")))))
				.andExpect(status().isOk())
				.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR]."));
	}

}
```
Same test with `@WithMockJwt` (need to import `com.c4-soft.springaddons`:`spring-security-oauth2-webmvc-test-addons` with test scope):
```java
    @Test
    @WithMockJwtAuth(authorities = { "NICE_GUY", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
    void test() throws Exception {
        mockMvc.perform(get("/greet"))
            .andExpect(status().isOk())
            .andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR]."));
    }
```

## Configuration cut-down
By adding a dependency on `com.c4-soft.springaddons`:`spring-security-oauth2-webmvc-addons:4.3.5`, we can greatly simply web-security configuration:
```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
public static class WebSecurityConfig {
}
```
All that is required is a few properties:
```
# shoud be set to where your authorization-server is
com.c4-soft.springaddons.security.token-issuers[0].location=https://localhost:9443/auth/realms/master

# shoud be configured with a list of private-claims this authorization-server puts user roles into
# below is default Keycloak conf for a `spring-addons` client with client roles mapper enabled
com.c4-soft.springaddons.security.token-issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons.roles

# use IDE auto-completion or see SpringAddonsSecurityProperties javadoc for complete configuration properties list
```
