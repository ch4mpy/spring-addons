/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.TestSecurityContextHolder;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsSecurity;

/**
 * <h2>Unit-test a secured service or repository which has injected dependencies</h2>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */

// Import security configuration and test component
@Import({ SecurityConfig.class, MessageService.class })
@AutoConfigureAddonsSecurity
class MessageServiceTests {

	// auto-wire tested component
	@Autowired
	private MessageService messageService;

	// mock dependencies
	@MockBean
	SecretRepo secretRepo;

	@BeforeEach
	public void setUp() {
		when(secretRepo.findSecretByUsername(anyString())).thenReturn("incredible");
	}

	@Test()
	void givenRequestIsAnonymous_whenGetSecret_thenThrows() {
		// call tested components methods directly (do not use MockMvc nor WebTestClient)
		assertThrows(Exception.class, () -> messageService.getSecret());
	}

	@Test()
	void givenRequestIsAnonymous_whenGetGreet_thenThrows() {
		assertThrows(Exception.class, () -> messageService.greet(null));
	}

	/*--------------*/
	/* @WithMockJwt */
	/*--------------*/
	@Test()
	@WithMockJwtAuth()
	void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecret_thenThrows() {
		assertThrows(Exception.class, () -> messageService.getSecret());
	}

	@Test
	@WithMockJwtAuth("ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecret_thenReturnsSecret() {
		assertThat(messageService.getSecret()).isEqualTo("incredible");
	}

	@Test
	@WithMockJwtAuth()
	void givenUserIsAuthenticated_whenGetGreet_thenReturnsGreeting() {
		final var auth = mock(JwtAuthenticationToken.class);
		final var token = mock(Jwt.class);
		when(token.getClaimAsString(StandardClaimNames.PREFERRED_USERNAME)).thenReturn("ch4mpy");
		when(auth.getToken()).thenReturn(token);
		when(auth.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_AUTHORIZED_PERSONNEL")));

		assertThat(messageService.greet(auth)).isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");

		assertThat(messageService.greet(auth)).isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}

	/*-------------------------*/
	/* @WithMockAuthentication */
	/*-------------------------*/
	@Test()
	@WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class)
	void givenUserIsAuthenticatedWithMockedAuthenticationButNotGrantedWithAuthorizedPersonnel_whenGetSecret_thenThrows() {
		assertThrows(Exception.class, () -> messageService.getSecret());
	}

	@Test
	@WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsAuthenticatedWithMockedAuthenticationAndGrantedWithAuthorizedPersonnel_whenGetSecret_thenReturnsSecret() {
		final var auth = (JwtAuthenticationToken) TestSecurityContextHolder.getContext().getAuthentication();
		when(auth.getTokenAttributes()).thenReturn(Map.of(StandardClaimNames.PREFERRED_USERNAME, "ch4mpy"));

		assertThat(messageService.getSecret()).isEqualTo("incredible");
	}

	@Test
	@WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class)
	void givenUserIsAuthenticatedWithMockedAuthentication_whenGetGreet_thenReturnsGreeting() {
		final var auth = mock(JwtAuthenticationToken.class);
		final var token = mock(Jwt.class);
		when(token.getClaimAsString(StandardClaimNames.PREFERRED_USERNAME)).thenReturn("ch4mpy");
		when(auth.getToken()).thenReturn(token);
		when(auth.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_AUTHORIZED_PERSONNEL")));

		assertThat(messageService.greet(auth)).isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}
}
