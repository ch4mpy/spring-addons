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
package com.c4_soft.oauth2;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Set;

import org.junit.Test;

import com.c4_soft.oauth2.OAuth2Authorization;
import com.c4_soft.oauth2.rfc6749.TokenType;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class OAuth2AuthorizationTest {

	@Test
	public void testFullConstructor() {
		final var actual = new OAuth2Authorization<>("access-token", TokenType.BEARER, "refresh-token", Instant.parse("2019-05-21T11:50:00Z"), Set.of("UNIT", "TEST"));
		assertThat(actual.getAccessToken()).isEqualTo("access-token");
		assertThat(actual.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(actual.getRefreshToken()).isEqualTo("refresh-token");
		assertThat(actual.getExpiresAt()).isEqualTo(Instant.parse("2019-05-21T11:50:00Z"));
		assertThat(actual.getScope()).containsExactlyInAnyOrder("UNIT", "TEST");
	}

	@Test
	public void testMiniConstructor() {
		final var actual = new OAuth2Authorization<>("access-token", TokenType.BEARER);
		assertThat(actual.getAccessToken()).isEqualTo("access-token");
		assertThat(actual.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(actual.getRefreshToken()).isNull();
		assertThat(actual.getExpiresAt()).isNull();
		assertThat(actual.getScope()).isEmpty();
	}

}
