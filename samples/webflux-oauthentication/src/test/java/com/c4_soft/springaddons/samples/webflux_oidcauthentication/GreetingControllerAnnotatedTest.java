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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockOidcAuth;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AutoConfigureAddonsSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webflux.WebTestClientSupport;

import reactor.core.publisher.Mono;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@WebFluxTest(GreetingController.class)
@AutoConfigureAddonsSecurity
@Import(SampleApi.WebSecurityConfig.class)
class GreetingControllerAnnotatedTest {

	@MockBean
	private MessageService messageService;

	@Autowired
	WebTestClientSupport api;

	@BeforeEach
	public void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final OAuthentication<OpenidClaimSet> auth = invocation.getArgument(0);
			return Mono.just(String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities()));
		});
		when(messageService.getSecret()).thenReturn(Mono.just("Secret message"));
	}

	@Test
	void greetWitoutAuthentication() throws Exception {
		api.get("https://localhost/greet").expectStatus().isUnauthorized();
	}

	@Test
	@WithMockOidcAuth
	void greetWithDefaultOAuthentication() throws Exception {
		api.get("https://localhost/greet").expectBody(String.class).isEqualTo("Hello user! You are granted with [ROLE_USER].");
	}

	@Test
	@WithMockOidcAuth(authorities = "ROLE_AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(sub = "Ch4mpy"))
	void greetCh4mpy() throws Exception {
		api.get("https://localhost/greet").expectBody(String.class).isEqualTo("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}

	@Test
	@WithMockOidcAuth
	void securedRouteWithoutAuthorizedPersonnelIsForbidden() throws Exception {
		api.get("https://localhost/secured-route").expectStatus().isForbidden();
	}

	@Test
	@WithMockOidcAuth("ROLE_AUTHORIZED_PERSONNEL")
	void securedRouteWithAuthorizedPersonnelIsOk() throws Exception {
		api.get("https://localhost/secured-route").expectStatus().isOk();
	}

	@Test
	@WithMockOidcAuth
	void securedMethodWithoutAuthorizedPersonnelIsForbidden() throws Exception {
		api.get("https://localhost/secured-method").expectStatus().isForbidden();
	}

	@Test
	@WithMockOidcAuth("ROLE_AUTHORIZED_PERSONNEL")
	void securedMethodWithAuthorizedPersonnelIsOk() throws Exception {
		api.get("https://localhost/secured-method").expectStatus().isOk();
	}
}
