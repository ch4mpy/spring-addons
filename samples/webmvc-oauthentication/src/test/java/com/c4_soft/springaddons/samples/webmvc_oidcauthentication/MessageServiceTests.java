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
package com.c4_soft.springaddons.samples.webmvc_oidcauthentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Import(MessageServiceTests.TestConfig.class)
@ExtendWith(SpringExtension.class)
class MessageServiceTests {

	@Autowired
	private MessageService messageService;

	@Test()
	void greetWitoutAuthentication() {
		assertThrows(Exception.class, () -> messageService.getSecret());
	}

	@Test
	@OpenId(authorities = "ROLE_AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(preferredUsername = "ch4mpy"))
	void greetWithMockJwtAuth() {
		@SuppressWarnings("unchecked")
		final OAuthentication<OpenidClaimSet> auth = (OAuthentication<OpenidClaimSet>) SecurityContextHolder.getContext().getAuthentication();

		assertThat(messageService.greet(auth)).isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}

	@Test()
	@OpenId()
	void secretWithoutAuthorizedPersonnelGrant() {
		assertThrows(Exception.class, () -> messageService.getSecret());
	}

	@Test
	@OpenId("ROLE_AUTHORIZED_PERSONNEL")
	void secretWithAuthorizedPersonnelRole() {
		assertThat(messageService.getSecret()).isEqualTo("Secret message");
	}

	@TestConfiguration(proxyBeanMethods = false)
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Import({ MessageService.class })
	static class TestConfig {
	}
}
