# How to configure a Spring REST API with token introspection

The aim here is to setup security for a spring-boot resource-server with end-users authenticated by **any OpenID authorization-server** (Keycloak, Auth0, MS Identity-Server, ...) using token introspection, so with possibly opaque tokens.

For each and every request it process, resource-servers will send a request to authorization-server to get token details. This can have **serious performance impact**. Are you sure you want to use token introspection and not JWT-decoder based security where authorization-server is accessed only once to retrieve signing key?

## Authorization-server requirements
Please refer to [tutorials prerequisits](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/README.md#prerequisites) first.

Introspection endpoint is reached using client-credentials flow.

For Keycloak, this means a client must be configured with:
- `confidential` "Access Type"
- "Service Accounts Enabled" activated
Create one if you don't have yet. You'll get client-secret from "credentials tab" once configuration saved.

Note you should have other (public) clients for the web / mobile apps identifying users and querying your resource-server.

From the authorization-server point of view, this means that access-tokens will be issued to a (public) client and introspected by other (confidential) client.

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
			<!-- use spring-addons-webflux-jwt-resource-server instead for reactive apps -->
			<artifactId>spring-addons-webmvc-introspecting-resource-server</artifactId>
			<version>6.0.8</version>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<!-- use spring-addons-webflux-test instead for reactive apps -->
			<artifactId>spring-addons-webmvc-introspecting-test</artifactId>
			<version>6.0.8</version>
			<scope>test</scope>
		</dependency>
```
`spring-addons-webmvc-introspecting-resource-server` internally uses `spring-boot-starter-oauth2-resource-server` and adds the following:
- Authorities mapping from token attribute(s) of your choice (with prefix and case processing)
- CORS configuration
- stateless session management (no servlet session, user "session" state in access-token only)
- disabled CSRF (no servlet session)
- 401 (unauthorized) instead of 302 (redirect to login) when authentication is missing or invalid on protected end-point
- list of routes accessible to unauthorized users (with anonymous enabled if this list is not empty)
all that from properties only

## Web-security config
`spring-oauth2-addons` comes with `@AutoConfiguration` for web-security config adapted to REST API projects. Just add 
```java
@Configuration
@EnableMethodSecurity
public static class SecurityConfig {
}
```

## `application.properties`:
```properties
## First define required spring-boot properties for token introspection
spring.security.oauth2.resourceserver.opaque-token.introspection-uri=https://localhost:8443/realms/master/protocol/openid-connect/token/introspect
spring.security.oauth2.resourceserver.opaque-token.client-id=spring-addons-public
spring.security.oauth2.resourceserver.opaque-token.client-secret=change-me

## Then add properties for authorities mapping and other addons features
# shoud be set to the value of iss attribute authorization-server returns when introspecting an access-token
com.c4-soft.springaddons.security.issuers[0].location=https://localhost:8443/realms/master

# shoud be configured with a list of private-claims this authorization-server puts user roles into
# below is default Keycloak conf for a `spring-addons` client with client roles mapper enabled
com.c4-soft.springaddons.security.issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons-public.roles,resource_access.spring-addons-confidential.roles

# use IDE auto-completion or see SpringAddonsSecurityProperties javadoc for complete configuration properties list
```

## Sample `@RestController`
``` java
@RestController
@RequestMapping("/greet")
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping()
	@PreAuthorize("hasAuthority('NICE')")
	public String getGreeting(BearerTokenAuthentication auth) {
		final var claims = new OpenidClaimSet(auth.getTokenAttributes());
		return "Hi %s! You are granted with: %s.".formatted(
				auth.getToken().getClaimAsString(StandardClaimNames.PREFERRED_USERNAME),
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

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockBearerTokenAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.introspecting.AutoConfigureAddonsWebSecurity;
import com.c4soft.springaddons.tutorials.ResourceServerWithOAuthenticationApplication.SecurityConfig;

@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebSecurity
@Import(SecurityConfig.class)
class GreetingControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	@Test
	@WithMockBearerTokenAuthentication(authorities = { "NICE", "AUTHOR" }, attributes = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void givenUserIsGrantedWithNice_whenGreet_thenOk() throws Exception {
		mockMvc.get("/greet").andExpect(status().isOk()).andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
	}

	@Test
	@WithMockBearerTokenAuthentication(authorities = { "AUTHOR" }, attributes = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void givenUserIsNotGrantedWithNice_whenGreet_thenForbidden() throws Exception {
		mockMvc.get("/greet").andExpect(status().isForbidden());
	}

	@Test
	void givenUserIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		mockMvc.get("/greet").andExpect(status().isUnauthorized());
	}
}
```

This sample was guiding you to build a servlet application (webmvc) with access-token introspection and spring default `Authentication` for introspection: `BearerTokenAuthentication`. If you need help to configure a resource-server for webflux (reactive) or JWT decoder or another type of authentication, please refer to [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples).