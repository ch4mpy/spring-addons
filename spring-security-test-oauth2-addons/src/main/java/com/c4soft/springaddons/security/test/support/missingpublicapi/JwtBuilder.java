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
package com.c4soft.springaddons.security.test.support.missingpublicapi;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import com.c4soft.oauth2.ModifiableClaimSet;
import com.c4soft.oauth2.rfc7519.JwtClaimSet;

/**
 * Builder for {@link Jwt}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 * @see JwtAuthenticationTokenBuilder
 * @see Jwt
 */
public class JwtBuilder<T extends JwtBuilder<T>> {
	protected String tokenValue;
	protected final JwtClaimSet.Builder<?> claimsBuilder = JwtClaimSet.builder();
	protected final ModifiableClaimSet headers = new ModifiableClaimSet();

	public T tokenValue(String tokenValue) {
		this.tokenValue = tokenValue;
		return downcast();
	}

	public T claim(String name, Object value) {
		this.claimsBuilder.claim(name, value);
		return downcast();
	}

	public T claims(Consumer<JwtClaimSet.Builder<?>> claimsConsumer) {
		claimsConsumer.accept(this.claimsBuilder);
		return downcast();
	}

	public T headers(Consumer<ModifiableClaimSet> headersConsumer) {
		headersConsumer.accept(this.headers);
		return downcast();
	}

	public Jwt build() {
		final var claims = claimsBuilder.build();
		return new Jwt(
				this.tokenValue,
				claims.getIssuedAt(),
				claims.getExpirationTime(),
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