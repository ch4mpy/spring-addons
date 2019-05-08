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
package org.springframework.security.test.support.introspection;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.StringCollectionAuthoritiesConverter;
import org.springframework.security.test.support.AuthenticationBuilder;
import org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2IntrospectionAuthenticationTokenBuilder<T extends OAuth2IntrospectionAuthenticationTokenBuilder<T>> implements AuthenticationBuilder<OAuth2IntrospectionAuthenticationToken> {
	private static final String AUTHORITIES_PREFIX = "SCOPE_";

	private static final Converter<Collection<String>, Collection<GrantedAuthority>> AUTHORITIES_CONVERTER =
			new StringCollectionAuthoritiesConverter(AUTHORITIES_PREFIX);

	protected final OAuth2AccessTokenBuilder token;
	private final Map<String, Object> tokenAttributes;

	public OAuth2IntrospectionAuthenticationTokenBuilder() {
		this.tokenAttributes = new HashMap<>();
		this.token = new OAuth2AccessTokenBuilder(this.tokenAttributes);
	}

	public T attribute(String name, Object value) {
		this.tokenAttributes.put(name, value);
		return downcast();
	}

	public T scopes(String... scopes) {
		token.scopes(scopes);
		return downcast();
	}

	public T subject(String subject) {
		token.subject(subject);
		return downcast();
	}

	public T token(Consumer<OAuth2AccessTokenBuilder> tokenBuilderConsumer) {
		tokenBuilderConsumer.accept(token);
		return downcast();
	}

	public T username(String name) {
		token.username(name);
		return downcast();
	}

	@Override
	public OAuth2IntrospectionAuthenticationToken build() {
		final OAuth2AccessToken accessToken = token.build();

		return new OAuth2IntrospectionAuthenticationToken(
				accessToken,
				tokenAttributes,
				AUTHORITIES_CONVERTER.convert(accessToken.getScopes()),
				tokenAttributes.containsKey(OAuth2IntrospectionClaimNames.USERNAME) ? tokenAttributes.get(OAuth2IntrospectionClaimNames.USERNAME).toString()
						: tokenAttributes.get(OAuth2IntrospectionClaimNames.SUBJECT).toString());
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}

}
