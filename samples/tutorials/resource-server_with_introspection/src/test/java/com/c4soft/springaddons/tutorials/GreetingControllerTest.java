package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockBearerTokenAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.introspecting.AutoConfigureAddonsWebSecurity;
import com.c4soft.springaddons.tutorials.ResourceServerWithOAuthenticationApplication.WebSecurityConfig;

@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebSecurity
@Import(WebSecurityConfig.class)
class GreetingControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	@Test
	@WithMockBearerTokenAuthentication(authorities = { "NICE", "AUTHOR" }, attributes = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void givenUserIsGrantedWithNice_whenGreet_thenOk() throws Exception {
		mockMvc.get("/greet").andExpect(status().isOk()).andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
	}

	@Test
	@WithMockBearerTokenAuthentication(authorities = { "AUTHOR" }, attributes = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void givenUserIsNotGrantedWithNice_whenGreet_thenForbidden() throws Exception {
		mockMvc.get("/greet").andExpect(status().isForbidden());
	}

	@Test
	void givenUserIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		mockMvc.get("/greet").andExpect(status().isUnauthorized());
	}

}
