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
package com.c4soft.oauth2.rfc6749;

import java.time.Instant;
import java.util.Collection;

import org.springframework.lang.Nullable;

import com.c4soft.oauth2.OAuth2Authorization;

/**
 * To be further extended if using so called "parameters" in the RFC-6749
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class OpaqueOAuth2Authorization extends OAuth2Authorization<String, String> {

	public OpaqueOAuth2Authorization(
			String accessToken,
			TokenType tokenType,
			@Nullable String refreshToken,
			@Nullable Instant expiresAt,
			@Nullable Collection<String> scope) {
		super(accessToken, tokenType, refreshToken, expiresAt, scope);
	}

	public OpaqueOAuth2Authorization(String accessToken, TokenType tokenType) {
		super(accessToken, tokenType);
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder extends OAuth2Authorization.Builder<Builder, String, String, OpaqueOAuth2Authorization> {
		@Override
		public OpaqueOAuth2Authorization build() {
			return new OpaqueOAuth2Authorization(accessToken, tokenType, refreshToken, expiresAt, scopes);
		}
	}
}
