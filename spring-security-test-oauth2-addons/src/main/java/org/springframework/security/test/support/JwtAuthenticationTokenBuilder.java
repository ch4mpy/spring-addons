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

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Helps configure a test JwtAuthenticationToken
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class JwtAuthenticationTokenBuilder extends AbstractOAuth2AuthenticationBuilder<JwtAuthenticationTokenBuilder, Jwt> {

	public static final String DEFAULT_TOKEN_VALUE = "test.jwt.value";

	public static final String DEFAULT_HEADER_NAME = "test-header";

	public static final String DEFAULT_HEADER_VALUE = "test-header-value";

	public static final Map<String, Object> DEFAULT_HEADERS =
			Collections.singletonMap(DEFAULT_HEADER_NAME, DEFAULT_HEADER_VALUE);

	private final Map<String, Object> headers = new HashMap<>();

	@Autowired
	public JwtAuthenticationTokenBuilder(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		super(authoritiesConverter, DEFAULT_TOKEN_VALUE);
	}

	/**
	 * @param jwt fully configured JWT
	 * @return pre-configured builder
	 */
	public JwtAuthenticationTokenBuilder jwt(Jwt token) {
		final Map<String, Object> claims = new HashMap<>(token.getClaims());
		putIfNotEmpty(JwtClaimNames.IAT, token.getIssuedAt(), claims);
		putIfNotEmpty(JwtClaimNames.EXP, token.getExpiresAt(), claims);

		return attributes(claims).tokenValue(token.getTokenValue()).headers(token.getHeaders());
	}

	public JwtAuthenticationTokenBuilder claim(String name, Object value) {
		return attribute(name, value);
	}

	public JwtAuthenticationTokenBuilder claims(Map<String, Object> claims) {
		return attributes(claims);
	}

	public JwtAuthenticationTokenBuilder header(String name, Object value) {
		this.headers.put(name, value);
		return downCast();
	}

	public JwtAuthenticationTokenBuilder headers(Map<String, Object> headers) {
		this.headers.clear();
		headers.entrySet().stream().forEach(e -> this.header(e.getKey(), e.getValue()));
		return downCast();
	}

	@Override
	public JwtAuthenticationTokenBuilder authoritiesConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		return super.authoritiesConverter(authoritiesConverter);
	}

	public JwtAuthenticationToken build() {
		if(!attributes.containsKey(JwtClaimNames.SUB)) {
			attributes.put(JwtClaimNames.SUB, Defaults.AUTH_NAME);
		}

		final Jwt token = new Jwt(
				tokenValue,
				(Instant) attributes.get(JwtClaimNames.IAT),
				(Instant) attributes.get(JwtClaimNames.EXP),
				headers.isEmpty() ? DEFAULT_HEADERS : headers,
						attributes);

		return new JwtAuthenticationToken(token, authoritiesConverter.convert(token));
	}

}
