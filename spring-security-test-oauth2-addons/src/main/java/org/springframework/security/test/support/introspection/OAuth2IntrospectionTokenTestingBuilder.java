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
package org.springframework.security.test.support.introspection;

import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.test.support.Defaults;
import org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionToken;
import org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionToken.OAuth2IntrospectionTokenBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class OAuth2IntrospectionTokenTestingBuilder extends OAuth2IntrospectionTokenBuilder<OAuth2IntrospectionTokenTestingBuilder> {
	public OAuth2IntrospectionTokenTestingBuilder() {
		tokenType(TokenType.BEARER);
		value(Defaults.BEARER_TOKEN_VALUE);
		subject(Defaults.SUBJECT);
		username(Defaults.AUTH_NAME);
	}

	@Override
	public OAuth2IntrospectionToken build() {
		if(super.getScopes().isEmpty()) {
			scopes(Defaults.SCOPES);
		}
		return super.build();
	}
}
