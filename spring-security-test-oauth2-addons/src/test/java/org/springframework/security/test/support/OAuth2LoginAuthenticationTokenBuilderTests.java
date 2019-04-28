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

import java.time.Instant;
import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2LoginAuthenticationTokenBuilderTests {
	private static final String CLIENT_ID = "test-client";
	OAuth2LoginAuthenticationTokenBuilder builder;

	@Before
	public void setUp() {
		builder = new OAuth2LoginAuthenticationTokenBuilder(AuthorizationGrantType.AUTHORIZATION_CODE)
				.nameAttributeKey(OAuth2IntrospectionClaimNames.USERNAME)
				.attribute(OAuth2IntrospectionClaimNames.USERNAME, "ch4mpy")
				.attribute(OAuth2IntrospectionClaimNames.SCOPE, "message:read")
				.openIdClaim(OAuth2IntrospectionClaimNames.USERNAME, "ch4mpy");

		/*
		builder.getClientRegistrationBuilder().authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientId(CLIENT_ID)
				.tokenUri("https://stub");

		builder.getAuthorizationRequestBuilder().authorizationUri("https://stub")
				.clientId(CLIENT_ID)
				.redirectUri("https://stub");
		*/
	}

	@Test
	public void authenticationNameIsSet() {
		final OAuth2LoginAuthenticationToken actual = builder.build();

		assertThat(actual.getName()).isEqualTo("ch4mpy");
	}

	@Test
	public void tokenIatIsSetFromClaims() {
		final OAuth2AccessToken actual =
				builder.attribute(OAuth2IntrospectionClaimNames.ISSUED_AT, Instant.parse("2019-03-21T13:52:25Z"))
						.build()
						.getAccessToken();

		assertThat(actual.getIssuedAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getExpiresAt()).isNull();
	}

	@Test
	public void tokenExpIsSetFromClaims() {
		final OAuth2AccessToken actual =
				builder.attribute(OAuth2IntrospectionClaimNames.EXPIRES_AT, Instant.parse("2019-03-21T13:52:25Z"))
						.build()
						.getAccessToken();

		assertThat(actual.getIssuedAt()).isNull();
		assertThat(actual.getExpiresAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
	}

	@Test
	public void scopeClaimAreAddedToAuthorities() {
		final OAuth2LoginAuthenticationToken actual =
				builder.attribute("scope", Collections.singleton("scope:claim TEST_AUTHORITY")).build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("SCOPE_TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

}
