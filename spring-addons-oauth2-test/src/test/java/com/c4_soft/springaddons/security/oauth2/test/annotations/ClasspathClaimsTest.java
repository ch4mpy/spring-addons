package com.c4_soft.springaddons.security.oauth2.test.annotations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
class ClasspathClaimsTest {

	@Test
	// @formatter:off
    @WithMockJwtAuth(
		authorities = { "ROLE_AUTHORIZED_PERSONNEL" },
		claims = @OpenIdClaims(
			usernameClaim = "$['https://c4-soft.com/user']['name']",
			jsonFile = @ClasspathClaims("ch4mp.json")))
    // @formatter:on
	void givenUserIsAuthenticatedWithJsonClaims_whenTestStarts_thenAuthenticationIsConfiguredInSecurityContext() throws Exception {
		final var auth = SecurityContextHolder.getContext().getAuthentication();
		final var authorities = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();

		assertEquals(JwtAuthenticationToken.class, auth.getClass());
		assertEquals("Ch4mp", auth.getName());
		assertThat(authorities).contains("ROLE_AUTHORIZED_PERSONNEL");
		assertEquals(1, authorities.size());
	}
}
