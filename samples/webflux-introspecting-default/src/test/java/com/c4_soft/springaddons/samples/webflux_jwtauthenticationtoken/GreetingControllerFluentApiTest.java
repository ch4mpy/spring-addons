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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOpaqueToken;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.OpaqueTokenMutator;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4_soft.springaddons.security.oauth2.test.mockmvc.introspecting.AutoConfigureAddonsWebSecurity;

import reactor.core.publisher.Mono;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@WebFluxTest(GreetingController.class)
@AutoConfigureAddonsWebSecurity
@Import({ SecurityConfig.class })
public class GreetingControllerFluentApiTest {
	static final AnonymousAuthenticationToken ANONYMOUS =
			new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@MockBean
	private MessageService messageService;

	@Autowired
	WebTestClient api;

	@BeforeEach
	public void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final BearerTokenAuthentication auth = invocation.getArgument(0, BearerTokenAuthentication.class);
			return Mono.just(String.format("Hello %s! You are granted with %s.", auth.getTokenAttributes().get(StandardClaimNames.PREFERRED_USERNAME), auth.getAuthorities()));
		});
		when(messageService.getSecret()).thenReturn(Mono.just("Secret message"));
	}

	@Test
	void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.mutateWith(SecurityMockServerConfigurers.mockAuthentication(ANONYMOUS)).get().uri("https://localhost/greet").exchange().expectStatus()
				.isUnauthorized();
	}

	@Test
	void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
		api.mutateWith(ch4mpy()).get().uri("https://localhost/greet").exchange().expectBody(String.class)
				.isEqualTo("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}

	@Test
	void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden() throws Exception {
		api.mutateWith(mockOpaqueToken()).get().uri("https://localhost/secured-route").exchange().expectStatus().isForbidden();
	}

	@Test
	void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden() throws Exception {
		api.mutateWith(mockOpaqueToken()).get().uri("https://localhost/secured-method").exchange().expectStatus().isForbidden();
	}

	@Test
	void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
		api.mutateWith(ch4mpy()).get().uri("https://localhost/secured-route").exchange().expectStatus().isOk();
	}

	@Test
	void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
		api.mutateWith(ch4mpy()).get().uri("https://localhost/secured-method").exchange().expectStatus().isOk();
	}

	private OpaqueTokenMutator ch4mpy() {
		return mockOpaqueToken().attributes(attributes -> attributes.put(StandardClaimNames.PREFERRED_USERNAME, "Ch4mpy"))
				.authorities(new SimpleGrantedAuthority("ROLE_AUTHORIZED_PERSONNEL"));
	}
}
