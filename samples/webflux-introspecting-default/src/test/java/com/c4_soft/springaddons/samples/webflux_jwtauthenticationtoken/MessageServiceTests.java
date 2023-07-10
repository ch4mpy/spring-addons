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
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.test.context.TestSecurityContextHolder;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.AuthenticationSource;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AddonsWebfluxComponentTest;

import reactor.core.publisher.Mono;

/**
 * <h2>Unit-test a secured service or repository which has injected dependencies</h2>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */

@AddonsWebfluxComponentTest
@SpringBootTest(classes = { SecurityConfig.class, MessageService.class })
class MessageServiceTests {

	// auto-wire tested component
	@Autowired
	private MessageService messageService;

	@Autowired
	private WithOpaqueToken.AuthenticationFactory authFactory;

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

	/*-------------------------------------*/
	/* @@WithMockBearerTokenAuthentication */
	/*-------------------------------------*/
	@Test()
	@WithOpaqueToken("tonton-pirate.json")
	void givenUserIsTontonPirate_whenGetSecret_thenThrows() {
		assertThrows(Exception.class, () -> messageService.getSecret().block());
	}

	@Test
	@WithOpaqueToken("ch4mp.json")
	void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecret_thenReturnsSecret() {
		assertThat(messageService.getSecret().block()).isEqualTo("incredible");
	}

	@ParameterizedTest
	@MethodSource("identities")
	void givenUserIsAuthenticated_whenGetGreet_thenReturnsGreeting(@ParameterizedAuthentication Authentication auth) {
		assertThat(messageService.greet((BearerTokenAuthentication) auth).block())
				.isEqualTo("Hello %s! You are granted with %s.".formatted(auth.getName(), auth.getAuthorities()));
	}

	Stream<Authentication> identities() {
		return authFactory.authenticationsFrom("ch4mp.json", "tonton-pirate.json");
	}

	/*-------------------------*/
	/* @WithMockAuthentication */
	/*-------------------------*/
	@Test()
	@WithMockAuthentication(authType = BearerTokenAuthentication.class, principalType = OAuth2AccessToken.class)
	void givenUserIsAuthenticatedWithMockedAuthenticationButNotGrantedWithAuthorizedPersonnel_whenGetSecret_thenThrows() {
		assertThrows(Exception.class, () -> messageService.getSecret().block());
	}

	@Test
	@WithMockAuthentication(authType = BearerTokenAuthentication.class, principalType = OAuth2AccessToken.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsAuthenticatedWithMockedAuthenticationAndGrantedWithAuthorizedPersonnel_whenGetSecret_thenReturnsSecret() {
		final var auth = (BearerTokenAuthentication) TestSecurityContextHolder.getContext().getAuthentication();
		when(auth.getTokenAttributes()).thenReturn(Map.of(StandardClaimNames.PREFERRED_USERNAME, "ch4mpy"));

		assertThat(messageService.getSecret().block()).isEqualTo("incredible");
	}

	@ParameterizedTest
	@AuthenticationSource({
			@WithMockAuthentication(
					authType = BearerTokenAuthentication.class,
					principalType = OAuth2AccessToken.class,
					name = "Ch4mpy",
					authorities = { "NICE", "AUTHOR" }),
			@WithMockAuthentication(
					authType = BearerTokenAuthentication.class,
					principalType = OAuth2AccessToken.class,
					name = "Tonton-Pirate",
					authorities = { "UNCLE", "SKIPPER" }) })
	void givenUserIsAuthenticatedWithMockedAuthentication_whenGetGreet_thenReturnsGreeting(@ParameterizedAuthentication Authentication auth) {
		assertThat(messageService.greet((BearerTokenAuthentication) auth).block())
				.isEqualTo("Hello %s! You are granted with %s.".formatted(auth.getName(), auth.getAuthorities()));
	}
}
