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
package com.c4_soft.springaddons.samples.webflux_oidcauthentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AutoConfigureAddonsSecurity;

/**
 * <h2>Unit-test a secured service or repository which has no dependencies</h2>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */

// Import security configuration and test component
@Import({ ServerProperties.class, OAuth2ResourceServerProperties.class, SecurityConfig.class, SecretRepo.class })
@AutoConfigureAddonsSecurity
@ExtendWith(SpringExtension.class)
class SecretRepoTest {

	// auto-wire tested component
	@Autowired
	SecretRepo secretRepo;

	@Test
	void whenNotAuthenticatedThenThrows() {
		// call tested components methods directly (do not use MockMvc nor WebTestClient)
		assertThrows(Exception.class, () -> secretRepo.findSecretByUsername("ch4mpy").block());
	}

	@Test
	@OpenId(claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenAuthenticatedAsSomeoneElseThenThrows() {
		assertThrows(Exception.class, () -> secretRepo.findSecretByUsername("ch4mpy").block());
	}

	@Test
	@OpenId(claims = @OpenIdClaims(preferredUsername = "ch4mpy"))
	void whenAuthenticatedWithSameUsernameThenReturns() {
		assertEquals("Don't ever tell it", secretRepo.findSecretByUsername("ch4mpy").block());
	}

}
