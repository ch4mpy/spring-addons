package com.c4_soft.springaddons.samples.webmvc.keycloak.web;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.samples.webmvc.keycloak.conf.KeycloakConfig;
import com.c4_soft.springaddons.samples.webmvc.keycloak.service.MessageService;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.WithMockKeycloakAuth;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak.ServletKeycloakAuthUnitTestingSupport;

@RunWith(SpringRunner.class)
@WebMvcTest(controllers = GreetingController.class)
@Import({ MockMvcSupport.class, ServletKeycloakAuthUnitTestingSupport.UnitTestConfig.class, KeycloakConfig.class })
public class GreetingControllerTest {
	private static final String GREETING = "Hello %s! You are granted with %s.";

	@MockBean
	private MessageService messageService;

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
	public void whenNoAuthenticationThenUnothorized() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockKeycloakAuth(name = "ch4mpy", authorities = { "USER", "AUTHORIZED_PERSONNEL" })
	public void whenAuthenticatedWithKeycloakAuthenticationTokenThenCanGreet() throws Exception {
		api.get("/greet")
				.andExpect(status().isOk())
				.andExpect(
						content().string(String.format(GREETING, "ch4mpy", List.of("USER", "AUTHORIZED_PERSONNEL"))));
	}

	@Test
	@WithMockKeycloakAuth(name = "ch4mpy", authorities = { "USER" })
	public void whenAuthenticatedWithoutAuthorizedPersonnelThenSecuredRouteIsForbidden() throws Exception {
		api.get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	@WithMockKeycloakAuth(name = "ch4mpy", authorities = { "AUTHORIZED_PERSONNEL" })
	public void whenAuthenticatedWithAuthorizedPersonnelThenSecuredRouteIsOk() throws Exception {
		api.get("/secured-route").andExpect(status().isOk());
	}
}
