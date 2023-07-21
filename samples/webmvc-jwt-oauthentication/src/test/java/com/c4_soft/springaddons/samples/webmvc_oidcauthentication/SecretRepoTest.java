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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.test.context.support.WithAnonymousUser;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsSecurity;

import jakarta.servlet.http.HttpServletRequest;

/**
 * <h2>Unit-test a secured service or repository which has no dependencies</h2>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */

// Import security configuration and test component
@EnableAutoConfiguration
@SpringBootTest(classes = { SecurityConfig.class, SecretRepo.class })
@AutoConfigureAddonsSecurity
class SecretRepoTest {

	// auto-wire tested component
	@Autowired
	SecretRepo secretRepo;

	@MockBean
	InMemoryClientRegistrationRepository clientRegistrationRepository;

	@MockBean
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenFindSecretByUsername_thenThrows() {
		// call tested components methods directly (do not use MockMvc nor WebTestClient)
		assertThrows(Exception.class, () -> secretRepo.findSecretByUsername("ch4mp"));
	}

	@Test
	@WithJwt("tonton-pirate.json")
	void givenUserIsAuthenticatedAsSomeoneElse_whenFindSecretByUsername_thenThrows() {
		assertThrows(Exception.class, () -> secretRepo.findSecretByUsername("ch4mp"));
	}

	@Test
	@WithJwt("ch4mp.json")
	void givenUserIsAuthenticatedAsSearchedUser_whenFindSecretByUsername_thenThrows() {
		assertEquals("Don't ever tell it", secretRepo.findSecretByUsername("ch4mp"));
	}

}
