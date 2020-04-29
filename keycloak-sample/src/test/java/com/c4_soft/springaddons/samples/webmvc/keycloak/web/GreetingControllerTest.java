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
import org.keycloak.adapters.springboot.KeycloakAutoConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.samples.webmvc.keycloak.conf.KeycloakConfig;
import com.c4_soft.springaddons.samples.webmvc.keycloak.service.MessageService;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.WithMockKeycloakAuth;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak.ServletKeycloakAuthUnitTestingSupport;

@RunWith(SpringRunner.class)
@SpringBootTest(
		classes = {
				MockMvcSupport.class,
				ServletKeycloakAuthUnitTestingSupport.UnitTestConfig.class,
				KeycloakConfig.class,
				GreetingController.class,
				KeycloakAutoConfiguration.class })
@AutoConfigureMockMvc
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
	@WithMockKeycloakAuth(name = "ch4mpy", authorities = { "USER", "AUTHORIZED_PERSONNEL" })
	public void whenAuthenticatedWithKeycloakAuthenticationTokenThenCanGreet() throws Exception {
		api.get("/greet")
				.andExpect(status().isOk())
				.andExpect(content().string(startsWith("Hello ch4mpy! You are granted with ")))
				.andExpect(content().string(containsString("AUTHORIZED_PERSONNEL")))
				.andExpect(content().string(containsString("USER")));
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
