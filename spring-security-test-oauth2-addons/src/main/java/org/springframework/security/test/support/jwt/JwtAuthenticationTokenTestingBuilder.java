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
package org.springframework.security.test.support.jwt;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.configuration.Defaults;

/**
 * Helps configure a {@link JwtAuthenticationToken}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 * @see JwtAuthenticationToken
 * @see JwtBuilder
 */
public class JwtAuthenticationTokenTestingBuilder extends JwtAuthenticationTokenBuilder<JwtAuthenticationTokenTestingBuilder> {
	public static final String DEFAULT_HEADER_NAME = "test-header";

	public static final String DEFAULT_HEADER_VALUE = "test-header-value";

	@Autowired
	public JwtAuthenticationTokenTestingBuilder(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		super(authoritiesConverter);
	}

	@Override
	public JwtAuthenticationToken build() {
		if(!jwt.hasTokenValue()) {
			jwt.tokenValue(Defaults.JWT_VALUE);
		}
		if(!jwt.hasName()) {
			jwt.claim(JwtClaimNames.SUB, Defaults.AUTH_NAME);
		}
		if(!jwt.hasHeader()) {
			jwt.header(DEFAULT_HEADER_NAME, DEFAULT_HEADER_VALUE);
		}

		return super.build();
	}
}
