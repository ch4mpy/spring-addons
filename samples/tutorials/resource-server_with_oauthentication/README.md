# How to configure a Spring REST API with `OAuthentication<OpenidClaimSet>`

The aim here is to setup security for a spring-boot resource-server with end-users authenticated by **any OpenID authorization-server** (Keycloak, Auth0, MS Identity-Server, ...).

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
			<version>4.4.7</version>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-test-webmvc-addons</artifactId>
			<version>4.4.7</version>
			<scope>test</scope>
		</dependency>
```

An other option would be to use one of `com.c4-soft.springaddons` archetypes (for instance `spring-webmvc-archetype-singlemodule` or `spring-webflux-archetype-singlemodule`)


## Web-security config
`spring-oauth2-addons` comes with `@AutoConfiguration` for web-security config adapted to REST API projects. Just add 
```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
public static class WebSecurityConfig {
}
```

## `application.properties`:
```properties
# shoud be set to where your authorization-server is
com.c4-soft.springaddons.security.token-issuers[0].location=https://localhost:9443/auth/realms/master

# shoud be configured with a list of private-claims this authorization-server puts user roles into
# below is default Keycloak conf for a `spring-addons` client with client roles mapper enabled
com.c4-soft.springaddons.security.token-issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons.roles

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
	@PreAuthorize("hasAuthority('NICE_GUY')")
	public String getGreeting(OAuthentication<OpenidClaimSet> auth) {
		return String.format(
			"Hi %s! You are granted with: %s.",
			auth.getClaims().getPreferredUsername(),
			auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")));
	}
}
```

## Unit-tests
```java
package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AutoConfigureSecurityAddons;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4soft.springaddons.tutorials.ResourceServerWithOAuthenticationApplication.WebSecurityConfig;

@WebMvcTest(GreetingController.class)
@AutoConfigureSecurityAddons
@Import(WebSecurityConfig.class)
class GreetingControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	@Test
	@OpenId(authorities = { "NICE_GUY", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenGrantedWithNiceGuyThenCanGreet() throws Exception {
		mockMvc
				.perform(get("/greet").secure(true))
				.andExpect(status().isOk())
				.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR]."));
	}

	@Test
	@OpenId(authorities = { "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenNotGrantedWithNiceGuyThenForbidden() throws Exception {
		mockMvc.perform(get("/greet").secure(true)).andExpect(status().isForbidden());
	}

}
```
