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
package com.c4_soft.springaddons.test.security.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Collection;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.test.security.support.introspection.OAuth2IntrospectionAuthenticationTokenTestingBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
public class OAuth2IntrospectionAuthenticationTokenTestingBuilderTests {

	@MockBean
	Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter;

	@Test
	public void authenticationNameAndTokenSubjectClaimAreSet() {
		final OAuth2IntrospectionAuthenticationToken actual = new OAuth2IntrospectionAuthenticationTokenTestingBuilder<>(authoritiesConverter)
				.token(accessToken -> accessToken.attributes(claims -> claims.username("ch4mpy")))
				.build();

		assertThat(actual.getName()).isEqualTo("ch4mpy");
		assertThat(actual.getTokenAttributes().get(OAuth2IntrospectionClaimNames.USERNAME)).isEqualTo("ch4mpy");
	}

	@Test
	public void tokenIatIsSetFromClaims() {
		final OAuth2AccessToken actual = new OAuth2IntrospectionAuthenticationTokenTestingBuilder<>(authoritiesConverter)
				.attribute(OAuth2IntrospectionClaimNames.ISSUED_AT, Instant.parse("2019-03-21T13:52:25Z"))
				.build()
				.getToken();

		assertThat(actual.getIssuedAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getExpiresAt()).isNull();
	}

	@Test
	public void tokenExpIsSetFromClaims() {
		final OAuth2AccessToken actual = new OAuth2IntrospectionAuthenticationTokenTestingBuilder<>(authoritiesConverter)
				.attribute(OAuth2IntrospectionClaimNames.EXPIRES_AT, Instant.parse("2019-03-21T13:52:25Z"))
				.build()
				.getToken();

		assertThat(actual.getIssuedAt()).isNull();
		assertThat(actual.getExpiresAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
	}

}
