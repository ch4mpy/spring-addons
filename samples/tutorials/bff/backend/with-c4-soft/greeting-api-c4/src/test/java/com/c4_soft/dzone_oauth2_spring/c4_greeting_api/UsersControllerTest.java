package com.c4_soft.dzone_oauth2_spring.c4_greeting_api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.stream.Stream;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;

@WebMvcTest(UsersController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
@Import(SecurityConf.class)
class UsersControllerTest {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	WithJwt.AuthenticationFactory authFactory;

	@Test
	@WithAnonymousUser
	void givenUserIsAnonymous_whenGetMe_thenOk() throws Exception {
		mockMvc.perform(get("/users/me")).andExpect(status().isOk()).andExpect(jsonPath("$.username").isEmpty());
	}

	@ParameterizedTest
	@MethodSource("identities")
	void givenUserIsAuthenticated_whenGetMe_thenOk(@ParameterizedAuthentication Authentication auth) throws Exception {
		mockMvc
				.perform(get("/users/me"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.username").value(auth.getName()))
				.andExpect(
						jsonPath("$.roles").value(Matchers.containsInAnyOrder(auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toArray())));
	}

	Stream<AbstractAuthenticationToken> identities() {
		return authFactory.authenticationsFrom("brice.json", "igor.json");
	}

}
