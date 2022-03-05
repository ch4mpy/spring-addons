package com.c4_soft.springaddons.samples.webmvc.keycloak.web;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.samples.webmvc.keycloak.KeycloakSpringBootSampleApp;
import com.c4_soft.springaddons.samples.webmvc.keycloak.service.MessageService;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak.ServletKeycloakAuthUnitTestingSupport;

@RunWith(SpringRunner.class)
@WebMvcTest(controllers = GreetingController.class)
@Import({ ServletKeycloakAuthUnitTestingSupport.class, KeycloakSpringBootSampleApp.KeycloakConfig.class })
// because this sample stands in the middle of non spring-boot-keycloak projects, Keycloak properties are isolated in
// application-keycloak.properties
@ActiveProfiles("keycloak")
public class GreetingControllerMockMvcPostProcessorTest {
	private static final String GREETING = "Hello %s! You are granted with %s.";

	@MockBean
	MessageService messageService;

	@MockBean
	JwtDecoder jwtDecoder;

	@Autowired
	MockMvc api;

	@Autowired
	ServletKeycloakAuthUnitTestingSupport keycloak;

	@Before
	public void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final Authentication auth = invocation.getArgument(0, Authentication.class);
			return String.format(GREETING, auth.getName(), auth.getAuthorities());
		});
	}

	@Test
	public void whenAuthenticatedWithKeycloakAuthenticationTokenThenCanGreet() throws Exception {
		api
				.perform(
						get("/greet")
								.with(
										keycloak
												.authentication()
												.authorities("AUTHORIZED_PERSONNEL", "USER")
												.accessToken(token -> token.setPreferredUsername("ch4mpy"))))
				.andExpect(status().isOk())
				.andExpect(content().string(startsWith("Hello ch4mpy! You are granted with ")))
				.andExpect(content().string(containsString("AUTHORIZED_PERSONNEL")))
				.andExpect(content().string(containsString("USER")));
	}

	@Test
	public void whenAuthenticatedWithoutAuthorizedPersonnelThenSecuredRouteIsForbidden() throws Exception {
		api
				.perform(get("/secured-route").with(keycloak.authentication().authorities("USER").accessToken(token -> token.setPreferredUsername("ch4mpy"))))
				.andExpect(status().isForbidden());
	}

	@Test
	public void whenAuthenticatedWithAuthorizedPersonnelThenSecuredRouteIsOk() throws Exception {
		api
				.perform(
						get("/secured-route")
								.with(keycloak.authentication().authorities("AUTHORIZED_PERSONNEL").accessToken(token -> token.setPreferredUsername("ch4mpy"))))
				.andExpect(status().isOk());
	}
}
