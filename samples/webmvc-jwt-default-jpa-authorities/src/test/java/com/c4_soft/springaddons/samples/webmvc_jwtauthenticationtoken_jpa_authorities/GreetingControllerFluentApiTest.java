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
package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

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
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockAuthenticationRequestPostProcessor;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;

import jakarta.persistence.EntityManagerFactory;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebSecurity
@Import({ SecurityConfig.class })
class GreetingControllerFluentApiTest {

	@MockBean
	private MessageService messageService;

	@Autowired
	MockMvcSupport api;

	@MockBean
	UserAuthorityRepository userAuthorityRepository;

	@MockBean(name = "entityManagerFactory")
	EntityManagerFactory entityManagerFactory;

	@BeforeEach
	public void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final JwtAuthenticationToken auth = invocation.getArgument(0, JwtAuthenticationToken.class);
			return String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities());
		});
		when(messageService.getSecret()).thenReturn("Secret message");
	}

	@Test
	void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}

	@Test
	void givenUserIsAuthenticated_whenGetGreet_thenOk() throws Exception {
		api.with(mockAuthentication(JwtAuthenticationToken.class, mock(Jwt.class)).name("user")).get("/greet")
				.andExpect(content().string("Hello user! You are granted with []."));
	}

	@Test
	void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
		api.with(ch4mpy()).get("/greet").andExpect(content().string("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
	}

	@Test
	void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden() throws Exception {
		api.with(mockAuthentication(JwtAuthenticationToken.class, mock(Jwt.class))).get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden() throws Exception {
		api.with(mockAuthentication(JwtAuthenticationToken.class, mock(Jwt.class))).get("/secured-method").andExpect(status().isForbidden());
	}

	@Test
	void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
		api.with(ch4mpy()).get("/secured-route").andExpect(status().isOk());
	}

	@Test
	void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
		api.with(ch4mpy()).get("/secured-method").andExpect(status().isOk());
	}

	private MockAuthenticationRequestPostProcessor<JwtAuthenticationToken> ch4mpy() {
		return mockAuthentication(JwtAuthenticationToken.class, mock(Jwt.class)).name("Ch4mpy").authorities("ROLE_AUTHORIZED_PERSONNEL");
	}
}
