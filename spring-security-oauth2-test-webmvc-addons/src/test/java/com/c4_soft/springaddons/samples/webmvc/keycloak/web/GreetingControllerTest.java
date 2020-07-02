package com.c4_soft.springaddons.samples.webmvc.keycloak.web;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.samples.webmvc.keycloak.KeycloakSpringBootSampleApp;
import com.c4_soft.springaddons.samples.webmvc.keycloak.service.MessageService;
import com.c4_soft.springaddons.security.oauth2.test.annotations.ClaimSet;
import com.c4_soft.springaddons.security.oauth2.test.annotations.StringClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.WithAccessToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.WithKeycloakIDToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.WithMockKeycloakAuth;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak.ServletKeycloakAuthUnitTestingSupport;

@RunWith(SpringRunner.class)
@WebMvcTest(controllers = GreetingController.class)
@Import({
		ServletKeycloakAuthUnitTestingSupport.UnitTestConfig.class,
		KeycloakSpringBootSampleApp.KeycloakConfig.class })
// because this sample stands in the middle of non spring-boot-keycloak projects, keycloakproperties are isolated in
// application-keycloak.properties
@ActiveProfiles("keycloak")
public class GreetingControllerTest {
	private static final String GREETING = "Hello %s! You are granted with %s.";

	@MockBean
	MessageService messageService;

	@MockBean
	JwtDecoder jwtDecoder;

	@Autowired
	MockMvcSupport api;

	@Before
	public void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final var auth = invocation.getArgument(0, Authentication.class);
			return String.format(GREETING, auth.getName(), auth.getAuthorities());
		});
	}

	@Test
	@WithMockKeycloakAuth(
			authorities = { "USER", "AUTHORIZED_PERSONNEL" },
			accessToken = @WithAccessToken(
					idToken = @WithKeycloakIDToken(
							subject = "42",
							preferredUsername = "ch4mpy",
							nickName = "Tonton-Pirate",
							otherClaims = @ClaimSet(stringClaims = @StringClaim(name = "foo", value = "bar"))),
					scope = "openid foo bar"),
			idToken = @WithKeycloakIDToken(
					subject = "42",
					preferredUsername = "ch4mpy",
					email = "ch4mp@c4-soft.com",
					emailVerified = true,
					nickName = "Tonton-Pirate",
					otherClaims = @ClaimSet(stringClaims = @StringClaim(name = "foo", value = "bar"))))
	public void whenAuthenticatedWithKeycloakAuthenticationTokenThenCanGreet() throws Exception {
		api.get("/greet")
				.andExpect(status().isOk())
				.andExpect(content().string(startsWith("Hello ch4mpy! You are granted with ")))
				.andExpect(content().string(containsString("AUTHORIZED_PERSONNEL")))
				.andExpect(content().string(containsString("USER")));
	}

	@Test
	@WithMockKeycloakAuth(
			authorities = { "USER" },
			accessToken = @WithAccessToken(idToken = @WithKeycloakIDToken(preferredUsername = "ch4mpy")))
	public void whenAuthenticatedWithoutAuthorizedPersonnelThenSecuredRouteIsForbidden() throws Exception {
		api.get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	@WithMockKeycloakAuth(
			authorities = { "AUTHORIZED_PERSONNEL" },
			accessToken = @WithAccessToken(idToken = @WithKeycloakIDToken(preferredUsername = "ch4mpy")))
	public void whenAuthenticatedWithAuthorizedPersonnelThenSecuredRouteIsOk() throws Exception {
		api.get("/secured-route").andExpect(status().isOk());
	}
}
