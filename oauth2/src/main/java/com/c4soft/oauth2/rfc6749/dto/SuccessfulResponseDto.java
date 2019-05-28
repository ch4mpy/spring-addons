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
package com.c4soft.oauth2.rfc6749.dto;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import com.c4soft.oauth2.rfc6749.TokenType;

/**
 * <p>Strict implementation of https://tools.ietf.org/html/rfc6749#section-5.1</p>
 * <p>Might be extended to add other so called "parameters" in the RFC.</p>
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 * @deprecated for illustration purpose only (useless for now)
 */
@Deprecated
public class SuccessfulResponseDto implements Serializable {
	private static final long serialVersionUID = -4029156671071046624L;

	private final String accessToken;

	@Nullable
	private final String refreshToken;

	private final String tokenType;

	@Nullable
	private final Long expiresIn;

	@Nullable
	private final String scope;

	@Nullable
	private final String state;

	public SuccessfulResponseDto(String accessToken, String tokenType, @Nullable String refreshToken, @Nullable Long expiresIn, @Nullable String scope, @Nullable String state) {
		Assert.hasText(accessToken, "accessToken must be non empty");
		Assert.hasText(tokenType, "tokenType must be non empty");
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.tokenType = tokenType;
		this.expiresIn = expiresIn;
		this.scope = scope;
		this.state = state;
	}

	public SuccessfulResponseDto(String accessToken, String tokenType) {
		this(accessToken, tokenType, null, null, null, null);
	}

	public String getAccessToken() {
		return accessToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public String getTokenType() {
		return tokenType;
	}

	public Long getExpiresIn() {
		return expiresIn;
	}

	public String getScope() {
		return scope;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {
		private String accessToken;
		private String refreshToken;
		private String tokenType;
		private Long expiresIn;
		private String scope;
		private String state;

		public Builder accessToken(Object accessToken) {
			this.accessToken = accessToken.toString();
			return this;
		}

		public Builder refreshToken(Object refreshToken) {
			this.refreshToken = refreshToken.toString();
			return this;
		}

		public Builder tokenType(String tokenType) {
			this.tokenType = tokenType;
			return this;
		}

		public Builder tokenType(TokenType tokenType) {
			this.tokenType = tokenType.value;
			return this;
		}

		public Builder expiresIn(Long expiresIn) {
			this.expiresIn = expiresIn;
			return this;
		}

		public Builder expiresAt(Instant expiresAt) {
			if(expiresAt == null) {
				this.expiresIn = null;
			} else {
				this.expiresIn = expiresAt.getEpochSecond() - Instant.now().getEpochSecond();
			}
			return this;
		}

		public Builder scope(String scope) {
			this.scope = scope;
			return this;
		}

		public Builder scope(Collection<String> scope) {
			this.scope = scope.stream().collect(Collectors.joining(" "));
			return this;
		}

		public Builder state(String state) {
			this.state = state;
			return this;
		}

		public SuccessfulResponseDto build() {
			return new SuccessfulResponseDto(accessToken, tokenType, refreshToken, expiresIn, scope, state);
		}
	}
}
