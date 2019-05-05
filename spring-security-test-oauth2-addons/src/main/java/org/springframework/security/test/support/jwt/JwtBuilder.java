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
package org.springframework.security.test.support.jwt;

import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimAccessor;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Helps configure a {@link Jwt}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 * @see JwtAuthenticationTokenBuilder
 * @see Jwt
 */
public class JwtBuilder implements JwtClaimAccessor {
	private String tokenValue;
	private final Map<String, Object> claims = new HashMap<>();
	private final Map<String, Object> headers = new HashMap<>();

	public JwtBuilder tokenValue(String tokenValue) {
		this.tokenValue = tokenValue;
		return this;
	}

	public JwtBuilder claim(String name, Object value) {
		this.claims.put(name, value);
		return this;
	}

	public JwtBuilder claims(Map<String, Object> claims) {
		this.claims.clear();
		this.claims.putAll(claims);
		return this;
	}

	public JwtBuilder header(String name, Object value) {
		this.headers.put(name, value);
		return this;
	}

	public JwtBuilder headers(Map<String, Object> headers) {
		this.headers.clear();
		headers.entrySet().stream().forEach(e -> this.header(e.getKey(), e.getValue()));
		return this;
	}

	public JwtBuilder jwt(JwtBuilder jwtBuilder) {
		return tokenValue(jwtBuilder.tokenValue).claims(jwtBuilder.claims).headers(jwtBuilder.headers);
	}

	public JwtBuilder jwt(Jwt jwt) {
		return tokenValue(jwt.getTokenValue()).claims(jwt.getClaims()).headers(jwt.getHeaders());
	}

	public Jwt build() {
		Assert.isTrue(hasTokenValue(), "token value must be set");
		Assert.isTrue(hasName(), "name must be set");
		Assert.isTrue(hasHeader(), "at least one header must be set");
		return new Jwt(
				this.tokenValue,
				getClaimAsInstant(JwtClaimNames.IAT),
				getClaimAsInstant(JwtClaimNames.EXP),
				new HashMap<>(this.headers),
				new HashMap<>(this.claims));
	}

	@Override
	public Map<String, Object> getClaims() {
		return Collections.unmodifiableMap(this.claims);
	}

	public JwtBuilder audience(List<String> audience) {
		this.claim(JwtClaimNames.AUD, new ArrayList<>(audience));
		return this;
	}

	public JwtBuilder expiresAt(Instant expiresAt) {
		this.claim(JwtClaimNames.EXP, expiresAt);
		return this;
	}

	public JwtBuilder jti(String jti) {
		this.claim(JwtClaimNames.JTI, jti);
		return this;
	}

	public JwtBuilder issuedAt(Instant issuedAt) {
		this.claim(JwtClaimNames.EXP, issuedAt);
		return this;
	}

	public JwtBuilder issuer(URL issuer) {
		this.claim(JwtClaimNames.SUB, issuer);
		return this;
	}

	public JwtBuilder notBefore(Instant notBefore) {
		this.claim(JwtClaimNames.EXP, notBefore);
		return this;
	}

	public JwtBuilder subject(String subject) {
		this.claim(JwtClaimNames.SUB, subject);
		return this;
	}

	public boolean hasTokenValue() {
		return StringUtils.hasLength(tokenValue);
	}

	public boolean hasName() {
		return StringUtils.hasLength(getClaimAsString(JwtClaimNames.SUB));
	}

	public boolean hasHeader() {
		return this.headers.size() > 0;
	}
}