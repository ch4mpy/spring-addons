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
package org.springframework.security.test.support.missingpublicapi;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

/**
 * Helps configure a {@link Jwt}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 * @see JwtAuthenticationTokenBuilder
 * @see Jwt
 */
public class JwtBuilder<T extends JwtBuilder<T>> {
	protected String tokenValue;
	protected final JwtClaimSet claims = new JwtClaimSet();
	protected final Map<String, Object> headers = new HashMap<>();

	public T tokenValue(String tokenValue) {
		this.tokenValue = tokenValue;
		return downcast();
	}

	public T claim(String name, Object value) {
		this.claims.put(name, value);
		return downcast();
	}

	public T claims(Map<String, Object> claims) {
		this.claims.clear();
		this.claims.putAll(claims);
		return downcast();
	}

	public T header(String name, Object value) {
		this.headers.put(name, value);
		return downcast();
	}

	public T headers(Map<String, Object> headers) {
		this.headers.clear();
		this.headers.putAll(headers);
		return downcast();
	}

	public Jwt build() {
		return new Jwt(
				this.tokenValue,
				claims.getClaimAsInstant(JwtClaimNames.IAT),
				claims.getClaimAsInstant(JwtClaimNames.EXP),
				this.headers,
				claims);
	}

	public T audience(Stream<String> audience) {
		this.claim(JwtClaimNames.AUD, audience.collect(Collectors.toList()));
		return downcast();
	}

	public T audience(Collection<String> audience) {
		return audience(audience.stream());
	}

	public T audience(String... audience) {
		return audience(Stream.of(audience));
	}

	public T expiresAt(Instant expiresAt) {
		this.claim(JwtClaimNames.EXP, expiresAt);
		return downcast();
	}

	public T jti(String jti) {
		this.claim(JwtClaimNames.JTI, jti);
		return downcast();
	}

	public T issuedAt(Instant issuedAt) {
		this.claim(JwtClaimNames.EXP, issuedAt);
		return downcast();
	}

	public T issuer(URL issuer) {
		this.claim(JwtClaimNames.SUB, issuer);
		return downcast();
	}

	public T notBefore(Instant notBefore) {
		this.claim(JwtClaimNames.EXP, notBefore);
		return downcast();
	}

	public T subject(String subject) {
		this.claim(JwtClaimNames.SUB, subject);
		return downcast();
	}
	
	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}
}