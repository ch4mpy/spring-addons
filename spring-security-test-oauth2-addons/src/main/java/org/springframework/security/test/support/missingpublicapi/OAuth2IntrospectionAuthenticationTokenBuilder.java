/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.test.support.missingpublicapi;

import java.util.Collection;
import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.StringCollectionAuthoritiesConverter;
import org.springframework.security.test.support.AuthenticationBuilder;
import org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionToken.OAuth2IntrospectionTokenBuilder;
import org.springframework.util.StringUtils;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2IntrospectionAuthenticationTokenBuilder<T extends OAuth2IntrospectionAuthenticationTokenBuilder<T>> implements AuthenticationBuilder<OAuth2IntrospectionAuthenticationToken> {
	private static final String AUTHORITIES_PREFIX = "SCOPE_";

	private static final Converter<Collection<String>, Collection<GrantedAuthority>> AUTHORITIES_CONVERTER =
			new StringCollectionAuthoritiesConverter(AUTHORITIES_PREFIX);

	protected final OAuth2IntrospectionTokenBuilder<?> tokenBuilder;

	public OAuth2IntrospectionAuthenticationTokenBuilder(OAuth2IntrospectionTokenBuilder<?> tokenBuilder) {
		this.tokenBuilder = tokenBuilder;
	}

	public OAuth2IntrospectionAuthenticationTokenBuilder() {
		this(new OAuth2IntrospectionTokenBuilder<>());
	}

	public T name(String subject) {
		tokenBuilder.username(subject);
		return downcast();
	}

	public T attribute(String name, Object value) {
		tokenBuilder.attribute(name, value);
		return downcast();
	}

	public T token(Consumer<OAuth2IntrospectionTokenBuilder<?>> tokenBuilderConsumer) {
		tokenBuilderConsumer.accept(tokenBuilder);
		return downcast();
	}

	@Override
	public OAuth2IntrospectionAuthenticationToken build() {
		final OAuth2IntrospectionToken token = tokenBuilder.build();
		final OAuth2AccessToken accessToken = new OAuth2AccessToken(TokenType.BEARER, token.getValue(), token.getIssuedAt(), token.getExpiresAt(), token.getScope());

		return new OAuth2IntrospectionAuthenticationToken(
				accessToken,
				token.getAttributes(),
				AUTHORITIES_CONVERTER.convert(token.getScope()),
				StringUtils.hasLength(token.getUsername()) ? token.getUsername() : token.getSubject());
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}

}
