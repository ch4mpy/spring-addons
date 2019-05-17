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
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.support.jwt.JwtAuthenticationTokenTestingBuilder;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
@Import(JwtAuthenticationTokenTestingBuilderTests.JwtAuthoritiesConverterConfiguration.class)
public class JwtAuthenticationTokenTestingBuilderTests {

	@Autowired
	Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

	JwtAuthenticationTokenTestingBuilder<?> authenticationBuilder;

	@Before
	public void setUp() {
		authenticationBuilder = new JwtAuthenticationTokenTestingBuilder<>(authoritiesConverter);
	}

	@Test
	public void defaultNameAndAuthority() {
		final JwtAuthenticationToken actual = authenticationBuilder.build();

		assertThat(actual.getName()).isEqualTo(Defaults.AUTH_NAME);
		assertThat(actual.getAuthorities()).isEmpty();
	}

	@Test
	public void defaultNameAndRoleOverides() {
		assertThat(authenticationBuilder.token(jwt -> jwt.claim(JwtClaimNames.SUB, "ch4mpy")).build().getName()).isEqualTo("ch4mpy");
		assertThat(authenticationBuilder.token(jwt -> jwt.claim("tst", "TEST")).build().getAuthorities())
				.containsExactly(new SimpleGrantedAuthority("TEST"));
	}

	@Test
	public void tokenIatAnExpAreSetFromClaims() {
		final Jwt actual = authenticationBuilder
				.token(jwt -> jwt
						.claim(JwtClaimNames.IAT, Instant.parse("2019-03-21T13:52:25Z"))
						.claim(JwtClaimNames.EXP, Instant.parse("2019-03-22T13:52:25Z")))
				.build()
				.getToken();

		assertThat(actual.getIssuedAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getExpiresAt()).isEqualTo(Instant.parse("2019-03-22T13:52:25Z"));
		assertThat(actual.getClaimAsInstant(JwtClaimNames.IAT)).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getClaimAsInstant(JwtClaimNames.EXP)).isEqualTo(Instant.parse("2019-03-22T13:52:25Z"));
	}

	@Test
	public void authoritiesConverterIsActuallyCalled() {
		final JwtAuthenticationToken actual = authenticationBuilder
				.token(jwt -> jwt.claim("tst", "scope:claim TEST_AUTHORITY"))
				.build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("TEST_AUTHORITY"),
				new SimpleGrantedAuthority("scope:claim"));
	}

	@Configuration
	public static class JwtAuthoritiesConverterConfiguration {
		@Bean
		Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
			return jwt -> Stream.of(jwt.containsClaim("tst") ? jwt.getClaimAsString("tst").split(" ") : new String[] {})
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toSet());
		}
	}

}
