/*
 * Copyright 2019 Jérôme Wacongne
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

package com.c4_soft.springaddons.test.security.context.support;

import static org.hamcrest.CoreMatchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.stream.Collectors;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.test.security.fixtures.GreetingApp;
import com.c4_soft.springaddons.test.security.fixtures.GreetingApp.GreetingController;
import com.c4_soft.springaddons.test.security.fixtures.MessageService;
import com.c4_soft.springaddons.test.security.web.servlet.request.ServletUnitTestingSupport;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
@WebMvcTest(GreetingController.class)
@ContextConfiguration(classes = GreetingApp.class)
@ComponentScan(basePackageClasses = { KeycloakSecurityComponents.class, KeycloakSpringBootConfigResolver.class })
public class GreetingControllerTests extends ServletUnitTestingSupport {
	@MockBean
	MessageService messageService;

	@Test
	@WithMockKeycloackAuth(name = "ch4mpy", roles = "TESTER")
	public void whenGreetIsReachedWithValidSecurityContextThenUserIsActuallyGreeted() throws Exception {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final var auth = (Authentication) invocation.getArgument(0);
			return String.format("Hello %s! You are granted with %s.", auth.getName(),
					auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
		});

		mockMvc().get("/greet").andExpect(content().string(is("Hello ch4mpy! You are granted with [ROLE_TESTER].")));
	}

	@Test
	@WithMockKeycloackAuth("TESTER")
	public void whenUserIsNotGrantedWithAuthorizedPersonelThenSecretRouteIsNotAccessible() throws Exception {
		mockMvc().get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	@WithMockKeycloackAuth("AUTHORIZED_PERSONNEL")
	public void whenUserIsGrantedWithAuthorizedPersonelThenSecretRouteIsAccessible() throws Exception {
		mockMvc().get("/secured-route").andExpect(content().string(is("secret route")));
	}

	@Test
	@WithMockKeycloackAuth("TESTER")
	public void whenUserIsNotGrantedWithAuthorizedPersonelThenSecretMethodIsNotAccessible() throws Exception {
		mockMvc().get("/secured-method").andExpect(status().isForbidden());
	}

	@Test
	@WithMockKeycloackAuth("AUTHORIZED_PERSONNEL")
	public void whenUserIsGrantedWithAuthorizedPersonelThenSecretMethodIsAccessible() throws Exception {
		mockMvc().get("/secured-method").andExpect(content().string(is("secret method")));
	}

}
