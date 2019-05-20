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
package com.c4soft.oauth2.rfc7519;

import java.time.Instant;
import java.util.Collection;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import com.c4soft.oauth2.OAuth2Authorization;
import com.c4soft.oauth2.rfc6749.TokenType;

/**
 * To be further extended if using so called "parameters" in the RFC-6749
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class JwtOAuth2Authorization extends OAuth2Authorization<JwtClaimSet, String> {

	public JwtOAuth2Authorization(JwtClaimSet accessToken, TokenType tokenType, @Nullable String refreshToken, @Nullable Instant expiresAt, @Nullable Collection<String> scope) {
		super(accessToken, tokenType, refreshToken, expiresAt, scope);
		if(expiresAt != null) {
			Assert.notNull(accessToken.getExpirationTime(), "access token expiration can't be null if authorization expires");
			Assert.isTrue(expiresAt.isAfter(accessToken.getExpirationTime()), "access token expiration must be after authorization one");
		}
	}

	public JwtOAuth2Authorization(JwtClaimSet accessToken, TokenType tokenType) {
		this(accessToken, tokenType, null, null, null);
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder extends OAuth2Authorization.Builder<Builder, JwtClaimSet, String, JwtOAuth2Authorization> {
		@Override
		public JwtOAuth2Authorization build() {
			return new JwtOAuth2Authorization(accessToken, tokenType, refreshToken, expiresAt, scope);
		}
	}
}
