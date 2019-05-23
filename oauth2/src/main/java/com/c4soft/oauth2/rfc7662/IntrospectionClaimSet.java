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
package com.c4soft.oauth2.rfc7662;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.c4soft.oauth2.ModifiableTokenProperties;
import com.c4soft.oauth2.UnmodifiableTokenProperties;
import com.c4soft.oauth2.rfc6749.TokenType;

/**
 * <p>Might be extended to add public or private claim accessors</p>
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class IntrospectionClaimSet extends UnmodifiableTokenProperties implements Principal {

	public IntrospectionClaimSet(Map<String, Object> claims) {
		super(claims);
	}

	@Override
	public String getName() {
		return getSubject();
	}

	public Boolean getActive() {
		return getAsBoolean(IntrospectionClaimNames.ACTIVE.value);
	}

	public Collection<String> getAudience() {
		return getAsStringSet(IntrospectionClaimNames.AUDIENCE.value);
	}

	public String getClientId() {
		return getAsString(IntrospectionClaimNames.CLIENT_ID.value);
	}

	public Instant getExpiresAt() {
		return getAsInstant(IntrospectionClaimNames.EXPIRES_AT.value);
	}

	public Instant getIssuedAt() {
		return getAsInstant(IntrospectionClaimNames.ISSUED_AT.value);
	}

	public URI getIssuer() throws URISyntaxException {
		return getAsUri(IntrospectionClaimNames.ISSUER.value);
	}

	public String getJti() {
		return getAsString(IntrospectionClaimNames.JTI.value);
	}

	public Instant getNotBefore() {
		return getAsInstant(IntrospectionClaimNames.NOT_BEFORE.value);
	}

	public Set<String> getScope() {
		return getAsStringSet(IntrospectionClaimNames.SCOPE.value);
	}

	public String getSubject() {
		return getAsString(IntrospectionClaimNames.SUBJECT.value);
	}

	public TokenType getTokenType() {
		final String str = getAsString(IntrospectionClaimNames.TOKEN_TYPE.value);
		if(str == null) {
			return null;
		}
		return TokenType.valueOf(str);
	}

	public String getUsername() {
		return getAsString(IntrospectionClaimNames.USERNAME.value);
	}

	public static Builder<?> builder() {
		return new Builder<>();
	}

	public static class Builder<T extends Builder<T>> {

		protected final ModifiableTokenProperties claimSet = new ModifiableTokenProperties();

		public T claim(String name, Object value) {
			claimSet.putOrRemove(name, value);
			return downcast();
		}

		public T active(Boolean active) {
			claimSet.putOrRemove(IntrospectionClaimNames.ACTIVE.value, active);
			return downcast();
		}

		public T audience(Stream<String> audience) {
			claimSet.putOrRemove(IntrospectionClaimNames.AUDIENCE.value, audience.collect(Collectors.toSet()));
			return downcast();
		}

		public T audience(String... audience) {
			return audience(Stream.of(audience));
		}

		public T audience(Collection<String> audience) {
			return audience(audience.stream());
		}

		public T clientId(String clientId) {
			claimSet.putOrRemove(IntrospectionClaimNames.CLIENT_ID.value, clientId);
			return downcast();
		}

		public T expirationTime(Instant expirationTime) {
			claimSet.putOrRemove(IntrospectionClaimNames.EXPIRES_AT.value, expirationTime);
			return downcast();
		}

		public T expiresIn(long seconds) {
			claimSet.putOrRemove(IntrospectionClaimNames.EXPIRES_AT.value, Instant.now().plus(Duration.ofSeconds(seconds)));
			return downcast();
		}

		public T issuedAt(Instant issuedAt) {
			claimSet.putOrRemove(IntrospectionClaimNames.ISSUED_AT.value, issuedAt);
			return downcast();
		}

		public T issuer(String issuer) {
			claimSet.putOrRemove(IntrospectionClaimNames.ISSUER.value, issuer);
			return downcast();
		}

		public T jwtId(String jwtId) {
			claimSet.putOrRemove(IntrospectionClaimNames.JTI.value, jwtId);
			return downcast();
		}

		public T notBefore(Instant notBefore) {
			claimSet.putOrRemove(IntrospectionClaimNames.NOT_BEFORE.value, notBefore);
			return downcast();
		}

		public T scope(Stream<String> scope) {
			claimSet.putOrRemove(IntrospectionClaimNames.SCOPE.value, scope.collect(Collectors.toSet()));
			return downcast();
		}

		public T scope(String... scope) {
			return scope(Stream.of(scope));
		}

		public T scope(Collection<String> scope) {
			return scope(scope.stream());
		}

		public T subject(String subject) {
			claimSet.putOrRemove(IntrospectionClaimNames.SUBJECT.value, subject);
			return downcast();
		}

		public T tokenType(TokenType tokenType) {
			claimSet.putOrRemove(IntrospectionClaimNames.TOKEN_TYPE.value, tokenType.value);
			return downcast();
		}

		public T username(String username) {
			claimSet.putOrRemove(IntrospectionClaimNames.USERNAME.value, username);
			return downcast();
		}

		public IntrospectionClaimSet build() {
			return new IntrospectionClaimSet(claimSet);
		}

		@SuppressWarnings("unchecked")
		protected T downcast() {
			return (T) this;
		}
	}
}
