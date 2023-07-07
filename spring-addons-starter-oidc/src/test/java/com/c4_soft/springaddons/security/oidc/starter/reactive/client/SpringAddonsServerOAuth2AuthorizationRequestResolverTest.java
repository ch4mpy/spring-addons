package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class SpringAddonsServerOAuth2AuthorizationRequestResolverTest {

	@Test
	void whenRequestPathMatchesAuthorizationCodePattern_thenClientRegistrationIdIsReturned() {
		final var actual = SpringAddonsServerOAuth2AuthorizationRequestResolver.resolveRegistrationId("/oauth2/authorization/authorization-code");
		assertEquals("authorization-code", actual);
	}

	@Test
	void whenRequestPatDoesNothMatcheAuthorizationCodePattern_thenClientRegistrationIdIsReturned() {
		final var actual = SpringAddonsServerOAuth2AuthorizationRequestResolver.resolveRegistrationId("/login/authorization/authorization-code");
		assertNull(actual);
	}

}
