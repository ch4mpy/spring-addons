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
package com.c4soft.oauth2;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import com.c4soft.oauth2.rfc6749.TokenType;

/**
 * Might be extended to add authorization properties
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 * @param <T> access-token type
 * @param <U> refresh-token type
 */
public class OAuth2Authorization<T, U> {

	private final T accessToken;

	@Nullable
	private final U refreshToken;

	private final TokenType tokenType;

	@Nullable
	private final Instant expiresAt;

	@Nullable
	private final Set<String> scope;

	public OAuth2Authorization(T accessToken, TokenType tokenType, @Nullable U refreshToken, @Nullable Instant expiresAt, @Nullable Collection<String> scope) {
		Assert.notNull(accessToken, "accessToken must be non null");
		Assert.notNull(tokenType, "tokenType must be non null");
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.tokenType = tokenType;
		this.expiresAt = expiresAt;
		this.scope = scope == null ? Collections.emptySet() : scope.stream().collect(Collectors.toSet());
	}

	public OAuth2Authorization(T accessToken, TokenType tokenType) {
		this(accessToken, tokenType, null, null, null);
	}

	public T getAccessToken() {
		return accessToken;
	}

	public U getRefreshToken() {
		return refreshToken;
	}

	public TokenType getTokenType() {
		return tokenType;
	}

	public Instant getExpiresAt() {
		return expiresAt;
	}

	public Set<String> getScope() {
		return scope;
	}

	public static abstract class Builder<
			THIS_TYPE extends Builder<THIS_TYPE, ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE, AUTHORIZATION_TYPE>,
			ACCESS_TOKEN_TYPE,
			REFRESH_TOKEN_TYPE,
			AUTHORIZATION_TYPE extends OAuth2Authorization<ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE>> {
		protected ACCESS_TOKEN_TYPE accessToken;
		protected REFRESH_TOKEN_TYPE refreshToken;
		protected TokenType tokenType;
		protected Instant expiresAt;
		protected Collection<String> scopes;

		public Builder() {
			this.tokenType = TokenType.BEARER;
			this.scopes = new HashSet<>();
		}

		public THIS_TYPE accessToken(ACCESS_TOKEN_TYPE accessToken) {
			this.accessToken = accessToken;
			return downcast();
		}

		public THIS_TYPE refreshToken(REFRESH_TOKEN_TYPE refreshToken) {
			this.refreshToken = refreshToken;
			return downcast();
		}

		public THIS_TYPE tokenType(TokenType tokenType) {
			this.tokenType = tokenType;
			return downcast();
		}

		public THIS_TYPE expiresAt(Instant expiresAt) {
			this.expiresAt = expiresAt;
			return downcast();
		}

		public THIS_TYPE expiresIn(Long seconds) {
			this.expiresAt = Instant.now().plus(Duration.ofSeconds(seconds));
			return downcast();
		}

		public THIS_TYPE scope(String scope) {
			Assert.hasLength(scope, "scope must be non empty");
			this.scopes.add(scope);
			return downcast();
		}

		public THIS_TYPE scopes(Stream<String> scopes) {
			this.scopes.clear();
			scopes.forEach(this::scope);
			return downcast();
		}

		public THIS_TYPE scopes(Collection<String> scopes) {
			return this.scopes(scopes.stream());
		}

		public THIS_TYPE scopes(String... scopes) {
			return this.scopes(Stream.of(scopes));
		}

		public abstract AUTHORIZATION_TYPE build();

		@SuppressWarnings("unchecked")
		protected THIS_TYPE downcast() {
			return (THIS_TYPE) this;
		}
	}
}
