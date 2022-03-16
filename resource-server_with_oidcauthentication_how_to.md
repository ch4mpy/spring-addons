# How to configure a Spring REST API with `OidcAuthentication<OidcToken>`

## Start a new project
You may start with https://start.spring.io/
Following dependencies will be needed:
- Spring Web
- OAuth2 Resource Server
- lombok

## Add dependencies to spring-addons
```xml
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-security-oauth2-addons</artifactId>
			<version>4.1.6</version>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<artifactId>spring-web-test-addons</artifactId>
			<version>4.1.6</version>
			<scope>test</scope>
		</dependency>
```

## Import web-security config
`spring-oauth2-addons` comes with configurable web-security config adapted to REST API projects.
Just add `com.c4_soft.springaddons.security.oauth2.config.synchronised` to components scanning:
```java
@SpringBootApplication(scanBasePackageClasses = { DemoApplication.class, OidcServletApiSecurityConfig.class })
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

}
```
and a few entries in `application.properties`:
```properties
com.c4-soft.springaddons.security.authorization-server-locations=https://localhost:9443/auth/realms/master,https://localhost:9443/auth/realms/other
com.c4-soft.springaddons.security.authorities-claims=realm_access.roles,resource_access.client1.roles,resource_access.client2.roles
com.c4-soft.springaddons.security.cors[0].path=/greet/**
com.c4-soft.springaddons.security.cors[0].allowed-origins=http://localhost,https://localhost,https://localhost:8100,https://localhost:4200
com.c4-soft.springaddons.security.permit-all=/actuator/health/readiness,/actuator/health/liveness,/v3/api-docs/**
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
	public String getGreeting(OidcAuthentication<OidcToken> auth) {
		return String
				.format(
						"Hi %s! You are granted with: %s.",
						auth.getToken().getPreferredUsername(),
						auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")));
	}
}
```

## Unit-tests
```java
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockOidcAuth;

@WebMvcTest
class GreetingControllerTest {

	@MockBean
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@Autowired
	MockMvc mockMvc;

	@Test
	@WithMockOidcAuth(authorities = { "NICE_GUY", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void test() throws Exception {
		mockMvc
				.perform(get("/greet").secure(true))
				.andExpect(status().isOk())
				.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR]."));
	}
}
```