package com.c4soft.springaddons.samples.bff.users.web;

import static org.hamcrest.collection.IsIterableContainingInAnyOrder.containsInAnyOrder;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithAnonymousUser;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;

@WebMvcTest(controllers = UsersController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
class UsersControllerTest {

	@Autowired
	MockMvcSupport api;

	@Autowired
	WithJwt.AuthenticationFactory authFactory;

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGetMe_thenOk() throws Exception {
		// @formatter:off
		api.get("/users/me")
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.name").value(""))
			.andExpect(jsonPath("$.exp").value(Long.MAX_VALUE))
			.andExpect(jsonPath("$.email").value(""))
			.andExpect(jsonPath("$.roles").isEmpty());
		// @formatter:on
	}

	@ParameterizedTest
	@MethodSource("allIdentities")
	void givenUserIsAuthenticated_whenGetMe_thenOk(@ParameterizedAuthentication Authentication auth) throws Exception {
		final var claims = new OpenidClaimSet(((JwtAuthenticationToken) auth).getTokenAttributes());
		final var authorities = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toArray();

		// @formatter:off
		api.get("/users/me")
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.name").value(claims.getPreferredUsername()))
			.andExpect(jsonPath("$.exp").value(claims.getExpiresAt().getEpochSecond()))
			.andExpect(jsonPath("$.email").value(claims.getEmail()))
			.andExpect(jsonPath("$.roles").value(containsInAnyOrder(authorities)));
		// @formatter:on
	}

	private Stream<AbstractAuthenticationToken> allIdentities() {
		final var authentications = authFactory.authenticationsFrom("ch4mp.json", "tonton-pirate.json").toList();
		return authentications.stream();
	}

}
