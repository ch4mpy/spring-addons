package com.c4_soft.springaddons.samples.webmvc_keycloakauthenticationtoken;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.WithMockKeycloakAuth;

@ExtendWith(SpringExtension.class)
@Import(MessageServiceTest.TestConfig.class)
class MessageServiceTest {

	@Autowired
	MessageService service;

	@WithMockKeycloakAuth(authorities = "USER", claims = @OpenIdClaims(preferredUsername = "ch4mpy"))
	void whenAuthenticatedWithoutAuthorizedPersonnelThenCanNotGetSecret() {
		assertThrows(AccessDeniedException.class, () -> service.getSecret());
	}

	@Test()
	@WithMockKeycloakAuth(authorities = "AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(preferredUsername = "ch4mpy"))
	void whenAuthenticatedWitAuthorizedPersonnelThenGetSecret() {
		final String actual = service.getSecret();
		assertEquals("Secret message", actual);
	}

	@Test
	void whenNotAuthenticatedThenCanNotGetGreeting() {
		assertThrows(Exception.class, () -> service.greet(null));
	}

	@Test()
	@WithMockKeycloakAuth(authorities = "AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(preferredUsername = "ch4mpy"))
	void whenAuthenticatedThenGetGreeting() {
		final String actual = service.greet((KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication());
		assertEquals("Hello ch4mpy! You are granted with [AUTHORIZED_PERSONNEL].", actual);
	}

	@TestConfiguration(proxyBeanMethods = false)
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Import({ MessageService.class })
	static class TestConfig {
		@Bean
		GrantedAuthoritiesMapper authoritiesMapper() {
			return new NullAuthoritiesMapper();
		}
	}
}
