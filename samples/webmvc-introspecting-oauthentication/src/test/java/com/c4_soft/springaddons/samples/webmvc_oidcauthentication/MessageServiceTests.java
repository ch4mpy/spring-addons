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
package com.c4_soft.springaddons.samples.webmvc_oidcauthentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsSecurity;

/**
 * <h2>Unit-test a secured service or repository which has injected dependencies</h2>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */

// Import security configuration and test component
@Import({ ServerProperties.class, OAuth2ResourceServerProperties.class, WebmvcIntrospectingOauthentication.SecurityConfig.class, MessageService.class })
@AutoConfigureAddonsSecurity
@ExtendWith(SpringExtension.class)
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
	void whenNotAuthenticatedGetSecretThrows() {
		// call tested components methods directly (do not use MockMvc nor WebTestClient)
		assertThrows(Exception.class, () -> messageService.getSecret());
	}

	@Test()
	void whenNotAuthenticatedGreetThrows() {
		assertThrows(Exception.class, () -> messageService.greet(null));
	}

	/*--------------*/
	/* @WithMockJwt */
	/*--------------*/
	@Test()
	@OpenId()
	void whenNotGrantedWithAuthorizedPersonelThenGetSecretThrows() {
		assertThrows(Exception.class, () -> messageService.getSecret());
	}

	@Test
	@OpenId("ROLE_AUTHORIZED_PERSONNEL")
	void whenGrantedWithAuthorizedPersonelThenGetSecretReturns() {
		assertThat(messageService.getSecret()).isEqualTo("incredible");
	}

	@Test
	@OpenId()
	void whenAuthenticatedThenGreetReurns() {
		final var auth = mock(OAuthentication.class);
		final var claims = new OpenidClaimSet(Map.of(StandardClaimNames.PREFERRED_USERNAME, "ch4mpy"));
		when(auth.getAttributes()).thenReturn(claims);
		when(auth.getPrincipal()).thenReturn(claims);
		when(auth.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_AUTHORIZED_PERSONNEL")));

		assertThat(messageService.greet(auth)).isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");

		assertThat(messageService.greet(auth)).isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}
}
