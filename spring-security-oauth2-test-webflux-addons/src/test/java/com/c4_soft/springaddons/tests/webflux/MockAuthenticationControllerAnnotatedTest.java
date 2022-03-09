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
package com.c4_soft.springaddons.tests.webflux;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.samples.webflux.OidcIdAuthenticationTokenReactiveApp;
import com.c4_soft.springaddons.samples.webflux.domain.MessageService;
import com.c4_soft.springaddons.samples.webflux.web.GreetingController;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webflux.WebTestClientSupport;

import reactor.core.publisher.Mono;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { GreetingController.class, OidcIdAuthenticationTokenReactiveApp.WebSecurityConfig.class })
@WebFluxTest(GreetingController.class)
@Import({ WebTestClientSupport.class })
public class MockAuthenticationControllerAnnotatedTest {
	@MockBean
	MessageService messageService;

	@Autowired
	WebTestClientSupport client;

	@MockBean
	ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver;

	@Before
	public void setUp() {
		when(messageService.greet(any(Authentication.class))).thenAnswer(invocation -> {
			final var auth = invocation.getArgument(0, Authentication.class);
			return Mono.just(String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities()));
		});
	}

	//@formatter:off
	@Test
	@WithMockAuthentication(JwtAuthenticationToken.class)
	public void testSpecifyingAuthenticationImplType() {
		client.get("https://localhost/greet")
			.expectStatus().isOk()
			.expectBody(String.class).isEqualTo("Hello user! You are granted with [ROLE_USER].");
	}

	@Test
	@WithMockAuthentication(JwtAuthenticationToken.class)
	public void testAccessSecuredEndpointWithoutRequiredAuthority() {
		client.get("https://localhost/secured-endpoint")
			.expectStatus().isForbidden();
	}

	@Test
	@WithMockAuthentication(JwtAuthenticationToken.class)
	public void testAccessSecuredMethodWithoutRequiredAuthority() {
		client.get("https://localhost/secured-method")
			.expectStatus().isForbidden();
	}

	@Test
	@WithMockAuthentication(name = "ch4mpy", authorities = {"ROLE_AUTHORIZED_PERSONNEL"})
	public void testGreetWithConfiguredAuthentication() {
		client.get("https://localhost/greet").expectBody(String.class)
			.isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}

	@Test
	@WithMockAuthentication(name = "ch4mpy", authorities = {"ROLE_AUTHORIZED_PERSONNEL"})
	public void testAccessSecuredEndpointWithRequiredAuthority() {
		client.get("https://localhost/secured-endpoint").expectBody(String.class)
			.isEqualTo("secret route");
	}

	@Test
	@WithMockAuthentication(name = "ch4mpy", authorities = {"ROLE_AUTHORIZED_PERSONNEL"})
	public void testAccessSecuredMethodWithRequiredAuthority() {
		client.get("https://localhost/secured-method").expectBody(String.class)
			.isEqualTo("secret method");
	}
	//@formatter:on
}
