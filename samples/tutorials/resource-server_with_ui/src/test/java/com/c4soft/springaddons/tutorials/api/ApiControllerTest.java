package com.c4soft.springaddons.tutorials.api;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;
import com.c4soft.springaddons.tutorials.ResourceServerWithUiProperties;
import com.c4soft.springaddons.tutorials.WebSecurityConfig;

@WebMvcTest(controllers = ApiController.class)
@AutoConfigureAddonsWebSecurity
@Import({ ResourceServerWithUiProperties.class, WebSecurityConfig.class })
class ApiControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	@Test
	@WithMockJwtAuth(
			authorities = { "NICE", "AUTHOR" },
			claims = @OpenIdClaims(usernameClaim = StandardClaimNames.PREFERRED_USERNAME, preferredUsername = "Tonton Pirate"))
	void givenUserIsAuthenticated_whenApiGreet_thenOk() throws Exception {
		mockMvc.get("/api/greet").andExpect(status().isOk()).andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
	}

	@Test
	void givenRequestIsAnonymous_whenApiGreet_thenUnauthorized() throws Exception {
		mockMvc.get("/api/greet").andExpect(status().isUnauthorized());
	}

}
