/*
 * Copyright 2019 Jérôme Wacongne
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
package com.c4_soft.oauth2.rfc6749;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;

import org.junit.Before;
import org.junit.Test;

import com.c4_soft.oauth2.rfc6749.OpaqueOAuth2Authorization;
import com.c4_soft.oauth2.rfc6749.TokenType;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class OpaqueOAuth2AuthorizationTest {

	OpaqueOAuth2Authorization.Builder builder;

	@Before
	public void setUp() {
		builder = OpaqueOAuth2Authorization.builder().accessToken("accessToken");
	}

	@Test(expected = RuntimeException.class)
	public void defaultBuilderThrowsException() {
		OpaqueOAuth2Authorization.builder().build();
	}

	@Test
	public void accessTokenIsEnoughAndTokenTypeIsDefaultedToBearer() {
		final var actual = builder.build();
		assertThat(actual.getAccessToken()).isEqualTo("accessToken");
		assertThat(actual.getTokenType()).isEqualTo(TokenType.BEARER);
	}

	@Test
	public void tokenTypeIsDefaultedToBearer() {
		assertThat(builder.build().getTokenType()).isEqualTo(TokenType.BEARER);
	}

	@Test
	public void tokenTypeActuallySetsTokenType() {
		assertThat(builder.tokenType(TokenType.MAC).build().getTokenType()).isEqualTo(TokenType.MAC);
	}

	@Test
	public void refreshTokenIsDefaultedToNull() {
		assertThat(builder.build().getRefreshToken()).isNull();
	}

	@Test
	public void refreshTokenActuallySetsRefreshToken() {
		assertThat(builder.refreshToken("refresh").build().getRefreshToken()).isEqualTo("refresh");
	}

	@Test
	public void expiresAtIsDefaultedToNull() {
		assertThat(builder.build().getExpiresAt()).isNull();
	}

	@Test
	public void expiresAtActualySetsExpiresAt() {
		final var now = Instant.now();
		assertThat(builder.expiresAt(now).build().getExpiresAt()).isEqualTo(now);
	}

	@Test
	public void expiresInSetsExpiresAt() {
		final var now = Instant.now();
		assertThat(builder.expiresIn(1L).build().getExpiresAt()).isBetween(now, now.plus(Duration.ofSeconds(2L)));
	}

	@Test
	public void scopeIsDefaultedToEmpty() {
		assertThat(builder.build().getScope()).isEmpty();
	}

	@Test
	public void scopeAddsToScope() {
		assertThat(builder.scope("UNIT").scope("TEST").build().getScope()).containsExactlyInAnyOrder("UNIT", "TEST");
	}


	@Test
	public void scopesResetsScope() {
		assertThat(builder.scopes("A", "B").scopes("UNIT", "TEST").build().getScope()).containsExactlyInAnyOrder("UNIT", "TEST");
	}
}
