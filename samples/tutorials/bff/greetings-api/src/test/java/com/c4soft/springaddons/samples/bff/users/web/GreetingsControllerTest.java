package com.c4soft.springaddons.samples.bff.users.web;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithAnonymousUser;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

@WebMvcTest(controllers = GreetingsController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
class GreetingsControllerTest {
	@Autowired
	MockMvcSupport api;

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGetGreetings_thenUnauthorized() throws Exception {
		api.get("/greetings").andExpect(status().isUnauthorized());
	}

	@Test
	@WithJwt("ch4mp_auth0.json")
	void givenUserIsAuthenticated_whenGetGreetings_thenOk() throws Exception {
		api.get("/greetings").andExpect(status().isOk());
	}

}
