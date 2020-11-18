/*
 * Copyright 2020 Jérôme Wacongne.
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
package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;

import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.oidc.IdTokenBuilder;

class IdTokenBuilderHelper {

	static <T extends IdTokenBuilder<T>> T feed(T token, IdTokenClaims tokenAnnotation) throws MalformedURLException {
		if (StringUtils.hasLength(tokenAnnotation.authTime())) {
			token.authTime(Instant.parse(tokenAnnotation.authTime()));
		}
		if (StringUtils.hasLength(tokenAnnotation.exp())) {
			token.expiresAt(Instant.parse(tokenAnnotation.exp()));
		}
		if (StringUtils.hasLength(tokenAnnotation.iat())) {
			token.issuedAt(Instant.parse(tokenAnnotation.iat()));
		}
		if (StringUtils.hasText(tokenAnnotation.iss())) {
			token.issuer(new URL(tokenAnnotation.iss()));
		}
		if (StringUtils.hasLength(tokenAnnotation.jti())) {
			token.jwtId(tokenAnnotation.jti());
		}
		if (StringUtils.hasLength(tokenAnnotation.nbf())) {
			token.notBefore(Instant.parse(tokenAnnotation.nbf()));
		}
		if (StringUtils.hasLength(tokenAnnotation.sessionState())) {
			token.sessionState(tokenAnnotation.sessionState());
		}
		return token.subject(tokenAnnotation.sub())
				.audience(Arrays.asList(tokenAnnotation.aud()))
				.nonce(tokenAnnotation.nonce())
				.acr(tokenAnnotation.acr())
				.amr(Arrays.asList(tokenAnnotation.amr()))
				.azp(tokenAnnotation.azp());
	}

}
