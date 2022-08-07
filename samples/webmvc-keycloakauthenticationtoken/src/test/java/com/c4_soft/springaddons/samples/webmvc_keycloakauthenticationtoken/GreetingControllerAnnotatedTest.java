package com.c4_soft.springaddons.samples.webmvc_keycloakauthenticationtoken;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.test.annotations.Claims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.JsonObjectClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.KeycloakAccess;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.KeycloakAccessToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.KeycloakAuthorization;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.KeycloakPermission;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.KeycloakResourceAccess;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.WithMockKeycloakAuth;

@WebMvcTest(controllers = GreetingController.class)
class GreetingControllerAnnotatedTest {
	private static final String GREETING = "Hello %s! You are granted with %s.";

	@MockBean
	MessageService messageService;

	@MockBean
	JwtDecoder jwtDecoder;

	@Autowired
	MockMvc api;

	@BeforeEach
	void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final var auth = invocation.getArgument(0, Authentication.class);
			return String.format(GREETING, auth.getName(), auth.getAuthorities());
		});
	}

	// @formatter:off
	@Test
	@WithMockKeycloakAuth(
			authorities = {"USER", "AUTHORIZED_PERSONNEL" },
			claims = @OpenIdClaims(
					sub = "42",
					jti = "123-456-789",
					nbf = "2020-11-18T20:38:00Z",
					sessionState = "987-654-321",
					email = "ch4mp@c4-soft.com",
					emailVerified = true,
					nickName = "Tonton-Pirate",
					preferredUsername = "ch4mpy",
					otherClaims = @Claims(jsonObjectClaims = @JsonObjectClaim(name = "foo", value = OTHER_CLAIMS))),
			accessToken = @KeycloakAccessToken(
					realmAccess = @KeycloakAccess(roles = { "TESTER" }),
					authorization = @KeycloakAuthorization(permissions = @KeycloakPermission(rsid = "toto", rsname = "truc", scopes = "abracadabra")),
					resourceAccess = {
							@KeycloakResourceAccess(resourceId = "resourceA", access = @KeycloakAccess(roles = {"A_TESTER"})),
							@KeycloakResourceAccess(resourceId = "resourceB", access = @KeycloakAccess(roles = {"B_TESTER"}))}))
	// @formatter:on
	void whenAuthenticatedWithKeycloakAuthenticationTokenThenCanGreet() throws Exception {
		api.perform(get("/greet")).andExpect(status().isOk()).andExpect(content().string(startsWith("Hello ch4mpy! You are granted with ")))
				.andExpect(content().string(containsString("AUTHORIZED_PERSONNEL"))).andExpect(content().string(containsString("USER")))
				.andExpect(content().string(containsString("TESTER"))).andExpect(content().string(containsString("A_TESTER")))
				.andExpect(content().string(containsString("B_TESTER")));
	}

	@Test
	@WithMockKeycloakAuth
	void testAuthentication() throws Exception {
		api.perform(get("/authentication")).andExpect(status().isOk()).andExpect(content().string("Hello user"));
	}

	@Test
	@WithMockKeycloakAuth
	void testPrincipal() throws Exception {
		api.perform(get("/principal")).andExpect(status().isOk()).andExpect(content().string("Hello user"));
	}

	static final String OTHER_CLAIMS = "{\"bar\":\"bad\", \"nested\":{\"deep\":\"her\"}, \"arr\":[1,2,3]}";
}
