package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
class ResourceServerWithUiApplicationTests {
	@Autowired
	MockMvcSupport api;

	@Test
	void givenRequestIsAnonymous_whenApiGreet_thenUnauthorized() throws Exception {
		api.get("/api/greet").andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockJwtAuth(
			authorities = { "NICE", "AUTHOR" },
			claims = @OpenIdClaims(usernameClaim = StandardClaimNames.PREFERRED_USERNAME, preferredUsername = "Tonton Pirate"))
	void givenUserIsAuthenticated_whenApiGreet_thenOk() throws Exception {
		api.get("/api/greet").andExpect(status().isOk()).andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
	}
}
