package com.c4soft.springaddons.samples.bff.users.web;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;

@WebMvcTest(controllers = UsersController.class)
@AutoConfigureAddonsWebSecurity
class UsersControllerTest {
	@Autowired
	MockMvcSupport api;

	@Test
	void givenRequestIsNotAuthorized_whenGetMe_thenUnauthorized() throws Exception {
		api.get("/users/me").andExpect(status().isUnauthorized());
	}

	@Test
	@OpenId
	void givenUserIsAuthenticated_whenGetMe_thenOk() throws Exception {
		api.get("/users/me").andExpect(status().isOk());
	}

}
