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
import java.util.Map;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class JwtAuthenticationTokenBuilderTests {

	private static JwtAuthenticationTokenBuilder newBuilder() {
		return new JwtAuthenticationTokenBuilder(new JwtGrantedAuthoritiesConverter());
	}

	@Test
	public void defaultNameAndAuthority() {
		final JwtAuthenticationToken actual = newBuilder().build();

		assertThat(actual.getName()).isEqualTo("user");
		assertThat(actual.getAuthorities()).isEmpty();
	}

	@Test
	public void defaultNameAndRoleOverides() {
		assertThat(newBuilder().attribute(JwtClaimNames.SUB, "ch4mpy").build().getName()).isEqualTo("ch4mpy");
		assertThat(newBuilder().attribute("scp", "TEST").build().getAuthorities())
				.containsExactly(new SimpleGrantedAuthority("SCOPE_TEST"));
	}

	@Test
	public void tokenIatIsSetFromClaims() {
		final Jwt actual = newBuilder()
				.attribute(JwtClaimNames.IAT, Instant.parse("2019-03-21T13:52:25Z"))
				.build()
				.getToken();

		assertThat(actual.getIssuedAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getExpiresAt()).isNull();
		assertThat(actual.getClaimAsInstant(JwtClaimNames.IAT)).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getClaimAsInstant(JwtClaimNames.EXP)).isNull();
	}

	@Test
	public void tokenExpIsSetFromClaims() {
		final Jwt actual = newBuilder()
				.attribute(JwtClaimNames.EXP, Instant.parse("2019-03-21T13:52:25Z"))
				.build()
				.getToken();

		assertThat(actual.getIssuedAt()).isNull();
		assertThat(actual.getExpiresAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getClaimAsInstant(JwtClaimNames.IAT)).isNull();
		assertThat(actual.getClaimAsInstant(JwtClaimNames.EXP)).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
	}

	@Test
	public void scopeClaimAreAddedToAuthorities() {
		final JwtAuthenticationToken actual = newBuilder()
				.attribute("scope", "scope:claim")
				.build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

	/**
	 * "scp" is the an usual name for "scope" claim
	 */

	@Test
	public void scpClaimAreAddedToAuthorities() {
		final JwtAuthenticationToken actual = newBuilder()
				.attribute("scp", "scope:claim TEST_AUTHORITY")
				.build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("SCOPE_TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

	@Test
	public void fromJwt() {
		final Jwt jwt = new Jwt(
				"test-token",
				null,
				null,
				Collections.singletonMap("test-header", "test"),
				Map.of(JwtClaimNames.SUB, "ch4mpy", "scp", "message:read message:write"));
		final JwtAuthenticationToken actual = newBuilder().jwt(jwt).build();
		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(new SimpleGrantedAuthority("SCOPE_message:read"), new SimpleGrantedAuthority("SCOPE_message:write"));
		assertThat(actual.getName()).isEqualTo("ch4mpy");
		assertThat(actual.getTokenAttributes()).hasSize(2);
		assertThat(actual.getTokenAttributes().get(JwtClaimNames.SUB)).isEqualTo("ch4mpy");
		assertThat(actual.getTokenAttributes().get("scp")).isEqualTo("message:read message:write");
	}

}
