/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.support;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.test.support.openid.OAuth2LoginAuthenticationTokenTestingBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2LoginAuthenticationTokenTestingBuilderTests {
	OAuth2LoginAuthenticationTokenTestingBuilder<?> builder;

	@Before
	public void setUp() {
		builder = new OAuth2LoginAuthenticationTokenTestingBuilder<>(AuthorizationGrantType.AUTHORIZATION_CODE)
				.name("ch4mpy")
				.scope("message:read");
	}

	@Test
	public void authenticationNameIsSet() {
		final OAuth2LoginAuthenticationToken actual = builder.build();

		assertThat(actual.getName()).isEqualTo("ch4mpy");
	}

	@Test
	public void scopesAreAddedToAuthorities() {
		final OAuth2LoginAuthenticationToken actual =
				builder.scopes("scope:claim").scope("TEST_AUTHORITY").build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("SCOPE_TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"),
				new SimpleGrantedAuthority("SCOPE_openid"));
	}

}
