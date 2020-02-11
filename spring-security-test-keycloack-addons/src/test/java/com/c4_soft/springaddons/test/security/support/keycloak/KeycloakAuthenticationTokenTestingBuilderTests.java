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
package com.c4_soft.springaddons.test.security.support.keycloak;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.test.security.support.Defaults;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
public class KeycloakAuthenticationTokenTestingBuilderTests {

	KeycloakAuthenticationTokenTestingBuilder<?> authenticationBuilder;

	@Before
	public void setUp() {
		authenticationBuilder = new KeycloakAuthenticationTokenTestingBuilder<>();
	}

	@Test
	public void defaultNameAndAuthority() {
		final var actual = authenticationBuilder.build();

		assertThat(actual.getName()).isEqualTo(Defaults.AUTH_NAME);
		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(new SimpleGrantedAuthority("ROLE_offline_access"),
				new SimpleGrantedAuthority("ROLE_uma_authorization"));
	}

	@Test
	public void defaultNameAndRoleOverides() {
		assertThat(authenticationBuilder.name("ch4mpy").build().getName()).isEqualTo("ch4mpy");
		assertThat(authenticationBuilder.roles("TEST").build().getAuthorities())
				.containsExactly(new SimpleGrantedAuthority("ROLE_TEST"));
	}

	@Test
	public void whenNameThenAccessTokenPreferedUsernameIsSet() {
		final var actual = authenticationBuilder.name("ch4mpy").build().getAccount().getKeycloakSecurityContext();

		assertThat(actual.getToken().getPreferredUsername()).isEqualTo("ch4mpy");
	}

	@Test
	public void whenRolesThenAccessTokenRealmAccessRolesIsSet() {
		final var actual = authenticationBuilder.roles("TEST").build().getAccount().getKeycloakSecurityContext();

		assertThat(actual.getToken().getRealmAccess().getRoles()).containsExactlyInAnyOrder("TEST");
	}

}
