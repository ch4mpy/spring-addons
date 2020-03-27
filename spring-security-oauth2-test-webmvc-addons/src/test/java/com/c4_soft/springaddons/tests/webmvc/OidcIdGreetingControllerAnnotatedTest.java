/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.tests.webmvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.samples.webmvc.common.domain.MessageService;
import com.c4_soft.springaddons.samples.webmvc.common.web.GreetingController;
import com.c4_soft.springaddons.samples.webmvc.oidcid.OidcIdServletApp;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockOidcId;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.JwtTestConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(
		classes = {
				GreetingController.class,
				OidcIdServletApp.WebSecurityConfig.class,
				MockMvcSupport.class,
				JwtTestConf.class })
@WebMvcTest(GreetingController.class)
public class OidcIdGreetingControllerAnnotatedTest {

	@MockBean
	private MessageService<OidcIdAuthenticationToken> messageService;

	@MockBean
	JwtOidcAuthenticationConverter authenticationConverter;

	@Autowired
	MockMvcSupport api;

	@Before
	public void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final var auth = invocation.getArgument(0, Authentication.class);
			return String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities());
		});
	}

	@Test
	public void greetWitoutAuthentication() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockOidcId()
	public void greetWithDefaultAuthentication() throws Exception {
		api.perform(get("/greet")).andExpect(content().string("Hello user! You are granted with [ROLE_USER]."));
	}

	@Test
	@WithMockOidcId(name = "Ch4mpy", authorities = "ROLE_AUTHORIZED_PERSONNEL")
	public void greetCh4mpy() throws Exception {
		api.get("/greet")
				.andExpect(content().string("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
	}

	@Test
	@WithMockOidcId()
	public void securedRouteWithoutAuthorizedPersonnelIsForbidden() throws Exception {
		api.get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	@WithMockOidcId()
	public void securedMethodWithoutAuthorizedPersonnelIsForbidden() throws Exception {
		api.get("/secured-method").andExpect(status().isForbidden());
	}

	@Test
	@WithMockOidcId("ROLE_AUTHORIZED_PERSONNEL")
	public void securedRouteWithAuthorizedPersonnelIsOk() throws Exception {
		api.get("/secured-route").andExpect(status().isOk());
	}

	@Test
	@WithMockOidcId("ROLE_AUTHORIZED_PERSONNEL")
	public void securedMethodWithAuthorizedPersonnelIsOk() throws Exception {
		api.get("/secured-method").andExpect(status().isOk());
	}

	static interface JwtOidcAuthenticationConverter extends Converter<Jwt, OidcIdAuthenticationToken> {
	}
}
