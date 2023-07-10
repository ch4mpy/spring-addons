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
package com.c4_soft.springaddons.samples.webmvc_oidcauthentication;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithAnonymousUser;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@WebMvcTest(GreetingController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
@Import({ SecurityConfig.class })
class GreetingControllerAnnotatedTest {

	@MockBean
	private MessageService messageService;

	@Autowired
	MockMvcSupport api;

	@Autowired
	WithOpaqueToken.AuthenticationFactory authFactory;

	@SuppressWarnings("unchecked")
	@BeforeEach
	public void setUp() {
		when(messageService.greet(any(OAuthentication.class))).thenAnswer(invocation -> {
			final OAuthentication<OpenidClaimSet> auth = invocation.getArgument(0, OAuthentication.class);
			return String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities());
		});
		when(messageService.getSecret()).thenReturn("Secret message");
	}

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}

	@ParameterizedTest
	@MethodSource("claimSets")
	void givenUserIsAuthenticated_whenGetGreet_thenOk(@ParameterizedAuthentication Authentication auth) throws Exception {
		api.get("/greet").andExpect(content().string("Hello %s! You are granted with %s.".formatted(auth.getName(), auth.getAuthorities())));
	}

	Stream<Authentication> claimSets() {
		return authFactory.authenticationsFrom("ch4mp.json", "tonton-pirate.json");
	}

	@Test
	@WithOpaqueToken("tonton-pirate.json")
	void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden() throws Exception {
		api.get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	@WithOpaqueToken("ch4mp.json")
	void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
		api.get("/secured-route").andExpect(status().isOk());
	}

	@Test
	@WithOpaqueToken("tonton-pirate.json")
	void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden() throws Exception {
		api.get("/secured-method").andExpect(status().isForbidden());
	}

	@Test
	@WithOpaqueToken("ch4mp.json")
	void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
		api.get("/secured-method").andExpect(status().isOk());
	}
}
