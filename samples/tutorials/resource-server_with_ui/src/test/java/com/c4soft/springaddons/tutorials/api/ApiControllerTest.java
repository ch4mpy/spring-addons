package com.c4soft.springaddons.tutorials.api;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithAnonymousUser;

import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;
import com.c4soft.springaddons.tutorials.TestAsCh4mp;
import com.c4soft.springaddons.tutorials.WebSecurityConfig;

@WebMvcTest(controllers = ApiController.class)
@AutoConfigureAddonsWebSecurity
@Import({ WebSecurityConfig.class })
class ApiControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	@Test
	@TestAsCh4mp
	void givenUserIsAuthenticated_whenApiGreet_thenOk() throws Exception {
		mockMvc.get("/api/greet").andExpect(status().isOk())
				.andExpect(content().string("Hi ch4mp! You are authenticated by https://dev-ch4mpy.eu.auth0.com/ and granted with: [NICE, AUTHOR]."));
	}

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenApiGreet_thenUnauthorized() throws Exception {
		mockMvc.get("/api/greet").andExpect(status().isUnauthorized());
	}

}
