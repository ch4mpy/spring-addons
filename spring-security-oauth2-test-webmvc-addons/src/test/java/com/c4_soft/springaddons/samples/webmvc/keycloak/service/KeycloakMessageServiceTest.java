package com.c4_soft.springaddons.samples.webmvc.keycloak.service;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
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
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OidcStandardClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.WithMockKeycloakAuth;

@RunWith(SpringRunner.class)
@Import(KeycloakMessageServiceTest.TestConfig.class)
public class KeycloakMessageServiceTest {

	@Autowired
	MessageService service;

	@Test(expected = AccessDeniedException.class)
	@WithMockKeycloakAuth(authorities = "USER", oidc = @OidcStandardClaims(preferredUsername = "ch4mpy"))
	public void whenAuthenticatedWithoutAuthorizedPersonnelThenCanNotGetSecret() {
		service.getSecret();
	}

	@Test()
	@WithMockKeycloakAuth(authorities = "AUTHORIZED_PERSONNEL", oidc = @OidcStandardClaims(preferredUsername = "ch4mpy"))
	public void whenAuthenticatedWitAuthorizedPersonnelThenGetSecret() {
		final var actual = service.getSecret();
		assertEquals("Secret message", actual);
	}

	@Test(expected = Exception.class)
	public void whenNotAuthenticatedThenCanNotGetGreeting() {
		service.greet(null);
	}

	@Test()
	@WithMockKeycloakAuth(authorities = "AUTHORIZED_PERSONNEL", oidc = @OidcStandardClaims(preferredUsername = "ch4mpy"))
	public void whenAuthenticatedThenGetGreeting() {
		final var actual = service.greet((KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication());
		assertEquals("Hello ch4mpy! You are granted with [AUTHORIZED_PERSONNEL].", actual);
	}

	@TestConfiguration(proxyBeanMethods = false)
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Import({ KeycloakMessageService.class })
	public static class TestConfig {
		@Bean
		public GrantedAuthoritiesMapper authoritiesMapper() {
			return new NullAuthoritiesMapper();
		}
	}
}
