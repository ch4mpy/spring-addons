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
package com.c4soft.springaddons.security.test.support.jwt;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

import com.c4soft.springaddons.security.test.support.Defaults;
import com.c4soft.springaddons.security.test.support.missingpublicapi.JwtBuilder;

/**
 * Builder with test default values for {@link Jwt}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class JwtTestingBuilder extends JwtBuilder<JwtTestingBuilder> {

	public static final String DEFAULT_HEADER_NAME = "test-header";

	public static final String DEFAULT_HEADER_VALUE = "test-header-value";

	public JwtTestingBuilder() {
		super();
		claimsBuilder.subject(Defaults.AUTH_NAME);
	}

	@Override
	public Jwt build() {
		if (!StringUtils.hasLength(tokenValue)) {
			tokenValue(Defaults.JWT_VALUE);
		}
		if (headers.size() == 0) {
			headers.put(DEFAULT_HEADER_NAME, DEFAULT_HEADER_VALUE);
		}
		return super.build();
	}
}