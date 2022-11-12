# How to configure a Spring REST API with `JwtAuthenticationToken` for a RESTful API

Be sure your environment meets [tutorials prerequisits](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/README.md#prerequisites).

We'll build web security configuration with `spring-boot-starter-oauth2-resource-server` and then greatly simplify it by using [`spring-addons-webmvc-jwt-resource-server`](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-addons-webmvc-jwt-resource-server).

Please note that `JwtAuthenticationToken` has a rather poor interface (not exposing OpenID standard claims for instance). For richer `Authentication` implementation, please have a look at [this other tutorial](https://github.com/ch4mpy/spring-addons/blob/master/resource-server_with_oidcauthentication_how_to.md).

## Start a new project
We'll start a spring-boot 3.0.0-RC2 project with the help of https://start.spring.io/
Following dependencies will be needed:
- Spring Web
- OAuth2 Resource Server
- Spring Boot Actuator
- lombok

We'll also need 
- `org.springframework.security`:`spring-security-test` with `test` scope
- `org.springdoc`:`springdoc-openapi-security`:`2.0.0-M6`
- `org.springdoc`:`springdoc-openapi-ui`:`2.0.0-M6`

## Create web-security config
A few specs for a REST API web security config:
- enable and configure CORS
- stateless session management (no servlet session, user "session" state in access-token only)
- disabled CSRF (no servlet session)
- enable anonymous
- return 401 instead of redirecting to login
- enable `@PreAuthorize()`

Let's do so the spring-boot 3 way (**not** extend `WebSecurityConfigurerAdapter`)
```java
package com.c4soft.springaddons.tutorials;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@Configuration
public class SecurityConfig {

    interface Jwt2AuthoritiesConverter extends Converter<Jwt, Collection<? extends GrantedAuthority>> {
    }

    @SuppressWarnings("unchecked")
    @Bean
    Jwt2AuthoritiesConverter authoritiesConverter() {
        // This is a converter for roles as embedded in the JWT by a Keycloak server
        // Roles are taken from both realm_access.roles & resource_access.{client}.roles
        return jwt -> {
            final var realmAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("realm_access", Map.of());
            final var realmRoles = (Collection<String>) realmAccess.getOrDefault("roles", List.of());

            final var resourceAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("resource_access", Map.of());
            // We assume here you have "spring-addons-confidential" and
            // "spring-addons-public" clients configured with "client roles" mapper in
            // Keycloak
            final var confidentialClientAccess = (Map<String, Object>) resourceAccess
                    .getOrDefault("spring-addons-confidential", Map.of());
            final var confidentialClientRoles = (Collection<String>) confidentialClientAccess.getOrDefault("roles",
                    List.of());
            final var publicClientAccess = (Map<String, Object>) resourceAccess.getOrDefault("spring-addons-public",
                    Map.of());
            final var publicClientRoles = (Collection<String>) publicClientAccess.getOrDefault("roles", List.of());

            return Stream
                    .concat(realmRoles.stream(),
                            Stream.concat(confidentialClientRoles.stream(), publicClientRoles.stream()))
                    .map(SimpleGrantedAuthority::new).toList();
        };
    }

    interface Jwt2AuthenticationConverter extends Converter<Jwt, AbstractAuthenticationToken> {
    }

    @Bean
    Jwt2AuthenticationConverter authenticationConverter(
            Converter<Jwt, Collection<? extends GrantedAuthority>> authoritiesConverter) {
        return jwt -> new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt));
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http,
            Converter<Jwt, AbstractAuthenticationToken> authenticationConverter,
            ServerProperties serverProperties)
            throws Exception {

        // Enable OAuth2 with custom authorities mapping
        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter);

        // Enable anonymous
        http.anonymous();

        // Enable and configure CORS
        http.cors().configurationSource(corsConfigurationSource());

        // State-less session (state in access-token only)
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // Disable CSRF because of state-less session-management
        http.csrf().disable();

        // Return 401 (unauthorized) instead of 302 (redirect to login) when
        // authorization is missing or invalid
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
        http.authorizeHttpRequests()
            .requestMatchers("/actuator/health/readiness", "/actuator/health/liveness", "/v3/api-docs", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
            .anyRequest().authenticated();
        // @formatter:on

        return http.build();
    }

    CorsConfigurationSource corsConfigurationSource() {
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
	@PreAuthorize("hasAuthority('NICE')")
	public String getGreeting(JwtAuthenticationToken auth) {
		return "Hi %s! You are granted with: %s.".formatted(
				auth.getToken().getClaimAsString(StandardClaimNames.PREFERRED_USERNAME),
				auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")));
	}
}
```

## application.properties
For a Keycloak listening on port 9443 on localhost:
```
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://localhost:8443/realms/master
```

## Unit-tests
You might use either `jwt` MockMvc request post processor from `org.springframework.security:spring-security-test` or `@WithMockJwt` from `com.c4-soft.springaddons:spring-addons-oauth2-test:6.0.4`.

Here is a sample usage for request post-processor:
```java
package com.c4soft.springaddons.tutorials;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(controllers = GreetingController.class, properties = "server.ssl.enabled=false")
@Import({ WebSecurityConfig.class })
class GreetingControllerTest {

	@MockBean
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@Autowired
	MockMvc mockMvc;

	@Test
	void whenGrantedNiceRoleThenOk() throws Exception {
		mockMvc.perform(get("/greet").with(jwt().jwt(jwt -> {
			jwt.claim("preferred_username", "Tonton Pirate");
		}).authorities(List.of(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR"))))).andExpect(status().isOk())
				.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
	}

	@Test
	void whenNotGrantedNiceRoleThenForbidden() throws Exception {
		mockMvc.perform(get("/greet").with(jwt().jwt(jwt -> {
			jwt.claim("preferred_username", "Tonton Pirate");
		}).authorities(List.of(new SimpleGrantedAuthority("AUTHOR"))))).andExpect(status().isForbidden());
	}

	@Test
	void whenAnonymousThenUnauthorized() throws Exception {
		mockMvc.perform(get("/greet")).andExpect(status().isUnauthorized());
	}

}
```
Same test with `@WithMockJwt` (need to import `com.c4-soft.springaddons`:`spring-addons-webmvc-jwt-test` with test scope):
```java
	@Autowired
	MockMvcSupport mockMvc;
	
    @Test
    @WithMockJwtAuth(authorities = { "NICE", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenGrantedWithNiceRoleThenCanGreet() throws Exception {
		mockMvc.get("/greet").andExpect(status().isOk()).andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
	}

	@Test
	@WithMockJwtAuth(authorities = { "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenNotGrantedWithNiceRoleThenForbidden() throws Exception {
		mockMvc.get("/greet").andExpect(status().isForbidden());
	}

	@Test
	void whenAnonymousThenUnauthorized() throws Exception {
		mockMvc.get("/greet").andExpect(status().isUnauthorized());
	}
```
And now an integration-test for the entire resource-server (still mocking OAuth2 authentications):
```java
@SpringBootTest(webEnvironment = WebEnvironment.MOCK, classes = { ResourceServerWithJwtAuthenticationTokenApplication.class, SecurityConfig.class })
@AutoConfigureMockMvc
class ResourceServerWithJwtAuthenticationTokenApplicationTests {
	@Autowired
	MockMvc api;

	@Autowired
	ServerProperties serverProperties;

	@Test
	void whenUserIsNotAuthorizedThenUnauthorized() throws Exception {
		api.perform(get("/greet").secure(isSslEnabled())).andExpect(status().isUnauthorized());
	}

	@Test
	void whenUserIsNotGrantedWithNiceAuthorityThenForbidden() throws Exception {
		api.perform(get("/greet").secure(isSslEnabled()).with(jwt())).andExpect(status().isForbidden());
	}

	@Test
	void whenUserIsGrantedWithNiceAuthorityThenGreeted() throws Exception {
		api.perform(
				get("/greet").secure(isSslEnabled()).with(
						jwt().authorities(List.of(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR")))
								.jwt(jwt -> jwt.claim(StandardClaimNames.PREFERRED_USERNAME, "Tonton Pirate"))))
				.andExpect(status().isOk()).andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
	}

	private boolean isSslEnabled() {
		return serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled();
	}

}
```
So what is so different from the preceding unit-tests? Not much in this tutorial because the controller is injected nothing. But if it was injected `@Service` or `@Repository` instances, those should be mocked in `@WebMvcTest` unit-tests and auto-wired (real instances) in `@SpringBootTest` integration-tests.

If you're not sure about the difference, please refer to samples(two nodes up in the folder tree) which have more complex secured controller with a secured service itself depending on a secured repository. All have unit and integration tests for all `@Components`.

## Configuration cut-down
`spring-addons-webmvc-jwt-resource-server` internally uses `spring-addons-webmvc-jwt-resource-server` and adds the following:
- Authorities mapping from token attribute(s) of your choice (with prefix and case processing)
- CORS configuration
- stateless session management (no servlet session, user "session" state in access-token only)
- disabled CSRF (no servlet session)
- 401 (unauthorized) instead of 302 (redirect to login) when authentication is missing or invalid on protected end-point
- list of routes accessible to unauthorized users (with anonymous enabled if this list is not empty)
all that from properties only

By replacing `spring-boot-starter-oauth2-resource-server` with `com.c4-soft.springaddons`:`spring-addons-webmvc-jwt-resource-server:6.0.0`, we can greatly simply web-security configuration:
```java
@EnableMethodSecurity(prePostEnabled = true)
public static class WebSecurityConfig {
}
```
All that is required is a few properties:
```
# shoud be set to where your authorization-server is
com.c4-soft.springaddons.security.issuers[0].location=https://localhost:8443/realms/master

# shoud be configured with a list of private-claims this authorization-server puts user roles into
# below is default Keycloak conf for a `spring-addons` client with client roles mapper enabled
com.c4-soft.springaddons.security.issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons-public.roles,resource_access.spring-addons-confidential.roles

# use IDE auto-completion or see SpringAddonsSecurityProperties javadoc for complete configuration properties list
```

This sample was guiding you to build a servlet application (webmvc) with JWT decoder and spring default `Authentication` JWTs: `JwtAuthenticationToken`. If you need help to configure a resource-server for webflux (reactive)  or access-token introspection or another type of authentication, please refer to [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples).
