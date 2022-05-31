package com.c4_soft.springaddons.samples.webflux_oidcauthentication;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockOidcAuth;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Import(MessageServiceTests.TestConfig.class)
@ExtendWith(SpringExtension.class)
class MessageServiceTests {

	@Autowired
	private MessageService messageService;

	@Test()
	void greetWitoutAuthentication() {
		assertThrows(Exception.class, () -> messageService.getSecret().block());
	}

	@Test
	@WithMockOidcAuth(authorities = "ROLE_AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(sub = "ch4mpy"))
	void greetWithMockJwtAuth() {
		@SuppressWarnings("unchecked")
		final OidcAuthentication<OidcToken> auth = (OidcAuthentication<OidcToken>) SecurityContextHolder.getContext().getAuthentication();

		assertThat(messageService.greet(auth).block()).isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}

	@Test()
	@WithMockOidcAuth()
	void secretWithoutAuthorizedPersonnelGrant() {
		assertThrows(Exception.class, () -> messageService.getSecret().block());
	}

	@Test
	@WithMockOidcAuth(authorities = "ROLE_AUTHORIZED_PERSONNEL")
	void secretWithAuthorizedPersonnelRole() {
		assertThat(messageService.getSecret().block()).isEqualTo("Secret message");
	}

	@TestConfiguration(proxyBeanMethods = false)
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Import({ MessageService.class })
	static class TestConfig {
	}
}
