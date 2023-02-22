package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;

import jakarta.servlet.http.HttpServletRequest;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
class ResourceServerWithJwtAuthenticationTokenApplicationTests {

	@MockBean
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@Autowired
	MockMvc api;

	@Autowired
	ServerProperties serverProperties;

	@Test
	void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		api.perform(get("/greet").secure(isSslEnabled())).andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockJwtAuth(
			authorities = { "NICE", "AUTHOR" },
			claims = @OpenIdClaims(usernameClaim = StandardClaimNames.PREFERRED_USERNAME, preferredUsername = "Tonton Pirate"))
	void givenUserAuthenticated_whenGreet_thenOk() throws Exception {
		// @formatter:off
		api.perform(get("/greet").secure(isSslEnabled()))
				.andExpect(status().isOk())
				.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
		// @formatter:on
	}

	private boolean isSslEnabled() {
		return serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled();
	}

}
