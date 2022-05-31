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

import static com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockAuthenticationRequestPostProcessor.mockAuthentication;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AutoConfigureSecurityAddons;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockAuthenticationRequestPostProcessor;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@WebMvcTest(GreetingController.class)
@AutoConfigureSecurityAddons
public class GreetingControllerFluentApiTest {

	@MockBean
	private MessageService messageService;

	@Autowired
	MockMvcSupport api;

	@BeforeEach
	public void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final JwtAuthenticationToken auth = invocation.getArgument(0, JwtAuthenticationToken.class);
			return String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities());
		});
		when(messageService.getSecret()).thenReturn("Secret message");
	}

	@Test
	void greetWitoutAuthentication() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}

	@Test
	void greetWithDefaultAuthentication() throws Exception {
		api
				.with(mockAuthentication(JwtAuthenticationToken.class, mock(Jwt.class)).name("user"))
				.get("/greet")
				.andExpect(content().string("Hello user! You are granted with [ROLE_USER]."));
	}

	@Test
	void greetCh4mpy() throws Exception {
		api.with(ch4mpy()).get("/greet").andExpect(content().string("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
	}

	@Test
	void securedRouteWithoutAuthorizedPersonnelIsForbidden() throws Exception {
		api.with(mockAuthentication(JwtAuthenticationToken.class, mock(Jwt.class))).get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	void securedMethodWithoutAuthorizedPersonnelIsForbidden() throws Exception {
		api.with(mockAuthentication(JwtAuthenticationToken.class, mock(Jwt.class))).get("/secured-method").andExpect(status().isForbidden());
	}

	@Test
	void securedRouteWithAuthorizedPersonnelIsOk() throws Exception {
		api.with(ch4mpy()).get("/secured-route").andExpect(status().isOk());
	}

	@Test
	void securedMethodWithAuthorizedPersonnelIsOk() throws Exception {
		api.with(ch4mpy()).get("/secured-method").andExpect(status().isOk());
	}

	private MockAuthenticationRequestPostProcessor<JwtAuthenticationToken> ch4mpy() {
		return mockAuthentication(JwtAuthenticationToken.class, mock(Jwt.class)).name("Ch4mpy").authorities("ROLE_AUTHORIZED_PERSONNEL");
	}
}
