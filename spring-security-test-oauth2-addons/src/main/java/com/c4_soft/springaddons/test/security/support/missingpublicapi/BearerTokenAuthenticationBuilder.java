/*
 * Copyright 2019 Jérôme Wacongne
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
package com.c4_soft.springaddons.test.security.support.missingpublicapi;

import java.util.Collection;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;

import com.c4_soft.springaddons.test.security.support.AuthenticationBuilder;
import com.c4_soft.springaddons.test.security.support.missingpublicapi.OAuth2IntrospectionToken.OAuth2IntrospectionTokenBuilder;

/**
 * Builder for {@link BearerTokenAuthentication}
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 * @param <T> capture for extending class type
 */
public class BearerTokenAuthenticationBuilder<T extends BearerTokenAuthenticationBuilder<T>>
		implements
		AuthenticationBuilder<BearerTokenAuthentication> {

	protected final Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter;
	protected final OAuth2IntrospectionTokenBuilder<?> tokenBuilder;

	public BearerTokenAuthenticationBuilder(
			Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter,
			OAuth2IntrospectionTokenBuilder<?> tokenBuilder) {
		this.authoritiesConverter = authoritiesConverter;
		this.tokenBuilder = tokenBuilder;
	}

	public BearerTokenAuthenticationBuilder() {
		this(SCOPE_AUTHORITIES_CONVERTER, new OAuth2IntrospectionTokenBuilder<>());
	}

	public T name(String subject) {
		tokenBuilder.attributes(claims -> claims.subject(subject).username(subject));
		return downcast();
	}

	public T attribute(String name, Object value) {
		tokenBuilder.attributes(claims -> claims.claim(name, value));
		return downcast();
	}

	public T token(Consumer<OAuth2IntrospectionTokenBuilder<?>> tokenBuilderConsumer) {
		tokenBuilderConsumer.accept(tokenBuilder);
		return downcast();
	}

	@Override
	public BearerTokenAuthentication build() {
		final OAuth2IntrospectionToken token = tokenBuilder.build();
		final OAuth2AccessToken accessToken = new OAuth2AccessToken(
				TokenType.BEARER,
				token.getTokenValue(),
				token.getAttributes().getIssuedAt(),
				token.getAttributes().getExpiresAt(),
				token.getAttributes().getScope());

		return new BearerTokenAuthentication(
				new DefaultOAuth2AuthenticatedPrincipal(token.getAttributes(), authoritiesConverter.convert(token.getAttributes())),
				accessToken,
				authoritiesConverter.convert(token.getAttributes()));
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}

	private static final String SCOPE_AUTHORITIES_PREFIX = "SCOPE_";

	private static final Converter<Map<String, Object>, Collection<GrantedAuthority>> SCOPE_AUTHORITIES_CONVERTER =
			claims -> extractScopes(claims).map(s -> new SimpleGrantedAuthority(SCOPE_AUTHORITIES_PREFIX + s))
					.collect(Collectors.toSet());

	private static Stream<String> extractScopes(Map<String, Object> claims) {
		final var scopeClaim = claims.containsKey("scope") ? claims.get("scope") : claims.get("scp");
		return scopeClaim == null ? Stream.empty() : Stream.of(scopeClaim.toString().split(" "));
	}

}
