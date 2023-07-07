/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.TestSecurityContextHolder;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AddonsWebfluxComponentTest;

import reactor.core.publisher.Mono;

/**
 * <h2>Unit-test a secured service or repository which has injected dependencies</h2>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */

// Import security configuration and test component
@AddonsWebfluxComponentTest
@SpringBootTest(classes = { SecurityConfig.class, MessageService.class })
class MessageServiceTests {

	// auto-wire tested component
	@Autowired
	private MessageService messageService;

	@Autowired
	WithJwt.AuthenticationFactory authFactory;

	// mock dependencies
	@MockBean
	SecretRepo secretRepo;

	@BeforeEach
	public void setUp() {
		when(secretRepo.findSecretByUsername(anyString())).thenReturn(Mono.just("incredible"));
	}

	@Test()
	void givenRequestIsAnonymous_whenGetSecret_thenThrows() {
		// call tested components methods directly (do not use MockMvc nor WebTestClient)
		assertThrows(Exception.class, () -> messageService.getSecret().block());
	}

	@Test()
	void givenRequestIsAnonymous_whenGetGreet_thenThrows() {
		assertThrows(Exception.class, () -> messageService.greet(null).block());
	}

	/*----------*/
	/* @WithJwt */
	/*----------*/
	@Test()
	@WithJwt("tonton-pirate.json")
	void givenUserIsTontonPirate_whenGetSecret_thenThrows() {
		assertThrows(Exception.class, () -> messageService.getSecret().block());
	}

	@Test
	@WithJwt("ch4mp.json")
	void givenUserIsCh4mp_whenGetSecret_thenReturnsSecret() {
		assertThat(messageService.getSecret().block()).isEqualTo("incredible");
	}

	@ParameterizedTest
	@MethodSource("auth0users")
	void givenUserIsPersona_whenGetGreet_thenReturnsGreeting(@ParameterizedAuthentication Authentication auth) {
		final var jwtAuth = (JwtAuthenticationToken) auth;
		assertThat(messageService.greet(jwtAuth).block()).isEqualTo("Hello %s! You are granted with %s.".formatted(auth.getName(), auth.getAuthorities()));
	}

	Stream<AbstractAuthenticationToken> auth0users() {
		return authFactory.authenticationsFrom("ch4mp.json", "tonton-pirate.json");
	}

	/*-------------------------*/
	/* @WithMockAuthentication */
	/*-------------------------*/
	@Test()
	@WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class)
	void givenUserIsAuthenticatedWithMockedAuthenticationButNotGrantedWithAuthorizedPersonnel_whenGetSecret_thenThrows() {
		assertThrows(Exception.class, () -> messageService.getSecret().block());
	}

	@Test
	@WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsAuthenticatedWithMockedAuthenticationAndGrantedWithAuthorizedPersonnel_whenGetSecret_thenReturnsSecret() {
		final var auth = (JwtAuthenticationToken) TestSecurityContextHolder.getContext().getAuthentication();
		when(auth.getTokenAttributes()).thenReturn(Map.of(StandardClaimNames.PREFERRED_USERNAME, "ch4mpy"));

		assertThat(messageService.getSecret().block()).isEqualTo("incredible");
	}

	@Test
	@WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class)
	void givenUserIsAuthenticatedWithMockedAuthentication_whenGetGreet_thenReturnsGreeting() {
		final var auth = mock(JwtAuthenticationToken.class);
		final var token = mock(Jwt.class);
		when(auth.getName()).thenReturn("ch4mpy");
		when(auth.getToken()).thenReturn(token);
		when(auth.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_AUTHORIZED_PERSONNEL")));

		assertThat(messageService.greet(auth).block()).isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}

}
