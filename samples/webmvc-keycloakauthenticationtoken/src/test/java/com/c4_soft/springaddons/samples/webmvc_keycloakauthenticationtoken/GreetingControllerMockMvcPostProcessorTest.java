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
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.samples.webmvc_keycloakauthenticationtoken.SampleApi.WebSecurityConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak.ServletKeycloakAuthUnitTestingSupport;

@WebMvcTest(controllers = GreetingController.class)
@Import({ ServletKeycloakAuthUnitTestingSupport.class, WebSecurityConf.class })
class GreetingControllerMockMvcPostProcessorTest {
	private static final String GREETING = "Hello %s! You are granted with %s.";

	@MockBean
	MessageService messageService;

	@MockBean
	JwtDecoder jwtDecoder;

	@Autowired
	MockMvc api;

	@Autowired
	ServletKeycloakAuthUnitTestingSupport keycloak;

	@BeforeEach
	void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final Authentication auth = invocation.getArgument(0, Authentication.class);
			return String.format(GREETING, auth.getName(), auth.getAuthorities());
		});
	}

	@Test
	void whenAuthenticatedWithKeycloakAuthenticationTokenThenCanGreet() throws Exception {
		api.perform(
				get("/greet")
						.with(keycloak.authentication().authorities("AUTHORIZED_PERSONNEL", "USER").accessToken(token -> token.setPreferredUsername("ch4mpy"))))
				.andExpect(status().isOk()).andExpect(content().string(startsWith("Hello ch4mpy! You are granted with ")))
				.andExpect(content().string(containsString("AUTHORIZED_PERSONNEL"))).andExpect(content().string(containsString("USER")));
	}

	@Test
	void whenAuthenticatedWithoutAuthorizedPersonnelThenSecuredRouteIsForbidden() throws Exception {
		api.perform(get("/secured-method").with(keycloak.authentication().authorities().accessToken(token -> token.setPreferredUsername("ch4mpy"))))
				.andExpect(status().isForbidden());
	}

	@Test
	void whenAuthenticatedWithAuthorizedPersonnelThenSecuredRouteIsOk() throws Exception {
		api.perform(
				get("/secured-method")
						.with(keycloak.authentication().authorities("AUTHORIZED_PERSONNEL").accessToken(token -> token.setPreferredUsername("ch4mpy"))))
				.andExpect(status().isOk());
	}
}
