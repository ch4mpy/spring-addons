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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.AttributesToStringCollectionToAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.StringCollectionAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.TokenAttributesStringListConverter;
import org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2IntrospectionAuthenticationTokenBuilder extends AbstractOAuth2AuthenticationBuilder<OAuth2IntrospectionAuthenticationTokenBuilder, Map<String, Object>> {
	public static final String DEFAULT_TOKEN_VALUE = "Bearer mocked token";
	private static final Converter<Map<String, Object>, List<String>> scopesConverter = TokenAttributesStringListConverter.builder().build();
	private static final Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter = new AttributesToStringCollectionToAuthoritiesConverter(
			scopesConverter,
			new StringCollectionAuthoritiesConverter("SCOPE_"));

	private TokenType tokenType;

	public OAuth2IntrospectionAuthenticationTokenBuilder() {
		super(authoritiesConverter, DEFAULT_TOKEN_VALUE);
		this.tokenType = TokenType.BEARER;
	}

	public OAuth2IntrospectionAuthenticationTokenBuilder tokenType(TokenType tokenType) {
		this.tokenType = tokenType;
		return downCast();
	}

	public OAuth2IntrospectionAuthenticationToken build() {
		attributes.put(OAuth2IntrospectionClaimNames.TOKEN_TYPE, tokenType);
		if(!attributes.containsKey(OAuth2IntrospectionClaimNames.USERNAME)) {
			attributes.put(OAuth2IntrospectionClaimNames.USERNAME, Defaults.AUTH_NAME);
		}
		if(!attributes.containsKey(OAuth2IntrospectionClaimNames.SCOPE)) {
			attributes.put(OAuth2IntrospectionClaimNames.SCOPE, Stream.of(Defaults.AUTHORITIES).collect(Collectors.joining(" ")));
		}

		final OAuth2AccessToken token = new OAuth2AccessToken(
				tokenType,
				tokenValue,
				(Instant) attributes.get(OAuth2IntrospectionClaimNames.ISSUED_AT),
				(Instant) attributes.get(OAuth2IntrospectionClaimNames.EXPIRES_AT),
				new HashSet<>(scopesConverter.convert(attributes)));

		return new OAuth2IntrospectionAuthenticationToken(
				token,
				attributes,
				authoritiesConverter.convert(attributes),
				attributes.get(OAuth2IntrospectionClaimNames.USERNAME).toString());
	}

}
