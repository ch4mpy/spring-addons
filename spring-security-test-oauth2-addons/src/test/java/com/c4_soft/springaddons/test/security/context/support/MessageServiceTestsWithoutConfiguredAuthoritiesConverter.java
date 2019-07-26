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
package com.c4_soft.springaddons.test.security.context.support;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.c4_soft.springaddons.test.security.context.support.message.MessageService;
import com.c4_soft.springaddons.test.security.web.servlet.request.JwtAuthenticationTokenUnitTestsParent;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringJUnit4ClassRunner.class)
@Import(MessageServiceTestsWithoutConfiguredAuthoritiesConverter.TestSecurityConfiguration.class)
public class MessageServiceTestsWithoutConfiguredAuthoritiesConverter extends JwtAuthenticationTokenUnitTestsParent {

	@Autowired
	private MessageService messageService;

	@Test(expected = AuthenticationCredentialsNotFoundException.class)
	public void greetWitoutMockJwt() {
		messageService.getGreeting();
	}

	@Test
	@WithMockJwt(name = "ch4mpy")
	public void greetWithMockJwt() {
		assertThat(messageService.getGreeting()).isEqualTo("Hello, ch4mpy!");
	}

	@Test(expected = AccessDeniedException.class)
	@WithMockJwt
	public void secretWithoutMessageReadScope() {
		assertThat(messageService.getSecret()).isEqualTo("Secret message");
	}

	@Test
	@WithMockJwt("message:read")
	public void secretWithScopeMessageReadAuthority() {
		assertThat(messageService.getSecret()).isEqualTo("Secret message");
	}

	@TestConfiguration
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@ComponentScan(basePackageClasses = MessageService.class)
	public static class TestSecurityConfiguration {}
}
