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
package com.c4_soft.springaddons.samples.webmvc.oidcid.web;

import static com.c4_soft.springaddons.security.oauth2.test.mockmvc.OidcIdAuthenticationTokenRequestPostProcessor.mockOidcId;
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
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.samples.webmvc.oidcid.OidcIdServletAppWithJwtEmbeddedAuthorities;
import com.c4_soft.springaddons.samples.webmvc.oidcid.service.MessageService;
import com.c4_soft.springaddons.security.oauth2.config.SecurityProperties;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.JwtTestConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.OidcIdAuthenticationTokenRequestPostProcessor;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {
		GreetingController.class,
		OidcIdServletAppWithJwtEmbeddedAuthorities.WebSecurityConfig.class,
		MockMvcSupport.class,
		JwtTestConf.class })
@WebMvcTest(GreetingController.class)
@Import(SecurityProperties.class)
public class OidcIdGreetingControllerFlowApiTest {

	@MockBean
	private MessageService messageService;

	@MockBean
	JwtOidcAuthenticationConverter authenticationConverter;

	@Autowired
	MockMvcSupport api;

	@Before
	public void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final Authentication auth = invocation.getArgument(0, Authentication.class);
			return String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities());
		});
	}

	@Test
	public void greetWitoutAuthentication() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}

	@Test
	public void greetWithDefaultAuthentication() throws Exception {
		api
				.with(mockOidcId().token(oidcId -> oidcId.subject("user")))
				.perform(get("/greet").secure(true))
				.andExpect(content().string("Hello user! You are granted with [ROLE_USER]."));
	}

	@Test
	public void greetCh4mpy() throws Exception {
		api.with(ch4mpy()).get("/greet").andExpect(content().string("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
	}

	@Test
	public void securedRouteWithoutAuthorizedPersonnelIsForbidden() throws Exception {
		api.with(mockOidcId()).get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	public void securedMethodWithoutAuthorizedPersonnelIsForbidden() throws Exception {
		api.with(mockOidcId()).get("/secured-method").andExpect(status().isForbidden());
	}

	@Test
	public void securedRouteWithAuthorizedPersonnelIsOk() throws Exception {
		api.with(ch4mpy()).get("/secured-route").andExpect(status().isOk());
	}

	@Test
	public void securedMethodWithAuthorizedPersonnelIsOk() throws Exception {
		api.with(ch4mpy()).get("/secured-method").andExpect(status().isOk());
	}

	private OidcIdAuthenticationTokenRequestPostProcessor ch4mpy() {
		return mockOidcId().token(oidcId -> oidcId.subject("Ch4mpy")).authorities("ROLE_AUTHORIZED_PERSONNEL");
	}

	interface JwtOidcAuthenticationConverter extends Converter<Jwt, OidcAuthentication> {
	}
}
