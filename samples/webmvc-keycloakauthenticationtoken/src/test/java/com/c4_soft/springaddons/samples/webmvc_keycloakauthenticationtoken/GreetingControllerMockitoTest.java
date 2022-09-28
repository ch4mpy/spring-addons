
package com.c4_soft.springaddons.samples.webmvc_keycloakauthenticationtoken;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.samples.webmvc_keycloakauthenticationtoken.SampleApi.WebSecurityConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak.ServletKeycloakAuthUnitTestingSupport;

@WebMvcTest(controllers = GreetingController.class)
@Import({ ServletKeycloakAuthUnitTestingSupport.UnitTestConfig.class, WebSecurityConf.class })
class GreetingControllerMockitoTest {
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
			final KeycloakAuthenticationToken auth = invocation.getArgument(0, KeycloakAuthenticationToken.class);
			return String.format(GREETING, auth.getAccount().getPrincipal().getName(), auth.getAccount().getRoles());
		});
	}

	@Test
	void whenAuthenticatedWithKeycloakAuthenticationTokenThenCanGreet() throws Exception {
		configureSecurityContext("ch4mpy", "USER", "AUTHORIZED_PERSONNEL", "TESTER");

		api.perform(get("/greet")).andExpect(status().isOk()).andExpect(content().string(startsWith("Hello ch4mpy! You are granted with ")))
				.andExpect(content().string(containsString("AUTHORIZED_PERSONNEL"))).andExpect(content().string(containsString("USER")))
				.andExpect(content().string(containsString("TESTER")));
	}

	@Test
	void whenAuthenticatedWithoutAuthorizedPersonnelThenSecuredRouteIsForbidden() throws Exception {
		configureSecurityContext("ch4mpy", "USER");

		api.perform(get("/secured-method")).andExpect(status().isForbidden());
	}

	@Test
	void whenAuthenticatedWithAuthorizedPersonnelThenSecuredRouteIsOk() throws Exception {
		configureSecurityContext("ch4mpy", "AUTHORIZED_PERSONNEL");

		api.perform(get("/secured-method")).andExpect(status().isOk());
	}

	private void configureSecurityContext(String username, String... roles) {
		final Principal principal = mock(Principal.class);
		when(principal.getName()).thenReturn(username);

		final OidcKeycloakAccount account = mock(OidcKeycloakAccount.class);
		when(account.getRoles()).thenReturn(new HashSet<>(Arrays.asList(roles)));
		when(account.getPrincipal()).thenReturn(principal);

		final KeycloakAuthenticationToken authentication = mock(KeycloakAuthenticationToken.class);
		when(authentication.getAccount()).thenReturn(account);
		when(authentication.getPrincipal()).thenReturn(account);
		when(authentication.getDetails()).thenReturn(account);
		when(authentication.getCredentials()).thenReturn(account);
		when(authentication.getAuthorities())
				.thenReturn(Stream.of(roles).map(s -> (GrantedAuthority) new SimpleGrantedAuthority(s)).collect(Collectors.toList()));

		when(authentication.isAuthenticated()).thenReturn(true);

		TestSecurityContextHolder.getContext().setAuthentication(authentication);
	}
}
