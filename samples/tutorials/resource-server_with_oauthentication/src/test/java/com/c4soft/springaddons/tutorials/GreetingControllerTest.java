package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsSecurityWebmvcJwt;
import com.c4soft.springaddons.tutorials.ResourceServerWithOAuthenticationApplication.WebSecurityConfig;

@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsSecurityWebmvcJwt
@Import(WebSecurityConfig.class)
class GreetingControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	@Test
	@OpenId(authorities = { "NICE_GUY", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenGrantedWithNiceGuyThenCanGreet() throws Exception {
		mockMvc.get("/greet").andExpect(status().isOk()).andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE_GUY, AUTHOR]."));
	}

	@Test
	@OpenId(authorities = { "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenNotGrantedWithNiceGuyThenForbidden() throws Exception {
		mockMvc.get("/greet").andExpect(status().isForbidden());
	}

}
