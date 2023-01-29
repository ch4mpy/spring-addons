# How to configure a Spring REST API with `OAuthentication<OpenidClaimSet>`

The aim here is to setup security for a spring-boot resource-server with end-users authenticated by **any OpenID authorization-server** (Keycloak, Auth0, MS Identity-Server, ...).

Be sure your environment meets [tutorials prerequisits](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/README.md#prerequisites).

## Start a new project
We'll start a spring-boot 3 project with the help of https://start.spring.io/
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
			<!-- use spring-addons-webflux-resource-server instead for reactive apps -->
			<artifactId>spring-addons-webmvc-resource-server</artifactId>
			<version>6.0.8</version>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<!-- use spring-addons-webflux-test instead for reactive apps -->
			<artifactId>spring-addons-webmvc-test</artifactId>
			<version>6.0.8</version>
			<scope>test</scope>
		</dependency>
```

An other option would be to use one of `com.c4-soft.springaddons` archetypes (for instance `spring-addons-archetypes-webmvc-singlemodule` or `spring-addons-archetypes-webflux-singlemodule`)

`spring-addons-webmvc-resource-server` internally uses `spring-boot-starter-oauth2-resource-server` and adds the following:
- Authorities mapping from token attribute(s) of your choice (with prefix and case processing)
- CORS configuration
- stateless session management (no servlet session, user "session" state in access-token only)
- disabled CSRF (no servlet session)
- 401 (unauthorized) instead of 302 (redirect to login) when authentication is missing or invalid on protected end-point
- list of routes accessible to unauthorized users (with anonymous enabled if this list is not empty)
all that from properties only

## Web-security config
`spring-oauth2-addons` comes with `@AutoConfiguration` for web-security config adapted to REST API projects. We'll just add:
- `@EnableMethodSecurity` to activate `@PreAuthorize` on components methods.
- provide an `OAuth2AuthenticationFactory` bean to switch `Authentication` implementation from `JwtAuthenticationToken` to `OAuthentication<OpenidClaimSet>`
```java
@Configuration
@EnableMethodSecurity
public static class SecurityConfig {
    @Bean
    OAuth2AuthenticationFactory authenticationFactory(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
        return (bearerString, claims) -> new OAuthentication<>(new OpenidClaimSet(claims),
                authoritiesConverter.convert(claims), bearerString);
    }
}
```

## `application.properties`:
```properties
# shoud be set to where your authorization-server is
com.c4-soft.springaddons.security.issuers[0].location=https://localhost:8443/realms/master

# shoud be configured with a list of private-claims this authorization-server puts user roles into
# below is default Keycloak conf for a `spring-addons` client with client roles mapper enabled
com.c4-soft.springaddons.security.issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons-public.roles,resource_access.spring-addons-confidential.roles

# use IDE auto-completion or see SpringAddonsSecurityProperties javadoc for complete configuration properties list
```

## Sample `@RestController`
Please note that OpenID standard claims can be accessed with getters (instead of Map<String, Object> like with JwtAuthenticationToken for instance)
``` java
@RestController
@RequestMapping("/greet")
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping()
	@PreAuthorize("hasAuthority('NICE')")
	public String getGreeting(OAuthentication<OpenidClaimSet> auth) {
		return "Hi %s! You are granted with: %s.".formatted(
				auth.getClaims().getPreferredUsername(),
				auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")));
	}
}
```

## Unit-tests
```java
package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.jwt.AutoConfigureAddonsWebSecurity;
import com.c4soft.springaddons.tutorials.ResourceServerWithOAuthenticationApplication.SecurityConfig;

@WebMvcTest(GreetingController.class)
@AutoConfigureAddonsWebSecurity
@Import(SecurityConfig.class)
class GreetingControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	@Test
	@OpenId(authorities = { "NICE", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenGrantedWithNiceRoleThenCanGreet() throws Exception {
		mockMvc.get("/greet").andExpect(status().isOk()).andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
	}

	@Test
	@OpenId(authorities = { "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenNotGrantedWithNiceRoleThenForbidden() throws Exception {
		mockMvc.get("/greet").andExpect(status().isForbidden());
	}

	@Test
	void whenAnonymousThenUnauthorized() throws Exception {
		mockMvc.get("/greet").andExpect(status().isUnauthorized());
	}
}
```

This sample was guiding you to build a servlet application (webmvc) with JWT decoder and `OAuthentication<OpenidClaimSet>`. If you need help to configure a resource-server for webflux (reactive)  or access-token introspection or another type of authentication, please refer to other tutorials and [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples).
