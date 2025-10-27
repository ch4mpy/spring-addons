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
package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

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
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

/**
 * <h2>Unit-test a secured controller</h2>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */

@WebMvcTest(GreetingController.class) // Use WebFluxTest or WebMvcTest
@AutoConfigureAddonsWebmvcResourceServerSecurity // If your web-security depends on it, setup spring-addons security
@Import({ SecurityConfig.class }) // Import your web-security configuration
class GreetingControllerAnnotatedTest {

	// Mock controller injected dependencies
	@MockitoBean
	private MessageService messageService;

	@Autowired
	MockMvcSupport api;

	@Autowired
	WithOpaqueToken.AuthenticationFactory authFactory;

	@BeforeEach
	public void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final BearerTokenAuthentication auth = invocation.getArgument(0, BearerTokenAuthentication.class);
			return String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities());
		});
		when(messageService.getSecret()).thenReturn("Secret message");
	}

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockAuthentication(authType = BearerTokenAuthentication.class, principalType = OAuth2AccessToken.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
	void givenUserHasMockedAuthenticated_whenGetGreet_thenOk() throws Exception {
		api.get("/greet").andExpect(content().string("Hello user! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
	}

	@ParameterizedTest
	@MethodSource("identities")
	void givenUserIsAuthenticated_whenGetGreet_thenOk(@ParameterizedAuthentication Authentication auth) throws Exception {
		api.get("/greet").andExpect(content().string("Hello %s! You are granted with %s.".formatted(auth.getName(), auth.getAuthorities())));
	}

	Stream<Authentication> identities() {
		return authFactory.authenticationsFrom("ch4mp.json", "tonton-pirate.json");
	}

	@Test
	@WithMockAuthentication(
			authType = BearerTokenAuthentication.class,
			principalType = OAuth2AccessToken.class,
			name = "Ch4mpy",
			authorities = "ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsMockedAsCh4mpy_whenGetGreet_thenOk() throws Exception {
		api.get("/greet").andExpect(content().string("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
	}

	@Test
	@WithOpaqueToken("ch4mp.json")
	void givenUserIsCh4mpy_whenGetSecuredRoute_thenOk() throws Exception {
		api.get("/secured-route").andExpect(status().isOk());
	}

	@Test
	@WithOpaqueToken("tonton-pirate.json")
	void givenUserIsTontonPirate_whenGetSecuredRoute_thenForbidden() throws Exception {
		api.get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	@WithMockAuthentication(authType = BearerTokenAuthentication.class, principalType = OAuth2AccessToken.class)
	void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden() throws Exception {
		api.get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	@WithMockAuthentication(authType = BearerTokenAuthentication.class, principalType = OAuth2AccessToken.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
		api.get("/secured-route").andExpect(status().isOk());
	}

	@Test
	@WithMockAuthentication(authType = BearerTokenAuthentication.class, principalType = OAuth2AccessToken.class)
	void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden() throws Exception {
		api.get("/secured-method").andExpect(status().isForbidden());
	}

	@Test
	@WithMockAuthentication(authType = BearerTokenAuthentication.class, principalType = OAuth2AccessToken.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
		api.get("/secured-method").andExpect(status().isOk());
	}
}
