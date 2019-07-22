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
package com.c4_soft.oauth2.rfc7662;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.c4_soft.oauth2.ModifiableClaimSet;
import com.c4_soft.oauth2.UnmodifiableClaimSet;
import com.c4_soft.oauth2.rfc6749.TokenType;

/**
 * <p>Might be extended to add public or private claim accessors</p>
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class IntrospectionClaimSet extends UnmodifiableClaimSet implements Principal {

	public IntrospectionClaimSet(Map<String, Object> claims) {
		super(claims);
	}

	@Override
	public String getName() {
		return getUsername();
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
		final Set<String> claim =  getAsStringSet(IntrospectionClaimNames.SCOPE.value);
		return claim == null ? Collections.emptySet() : claim;
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

	public static class Builder<T extends Builder<T>> extends ModifiableClaimSet {
		private static final long serialVersionUID = -6994538451749533929L;

		public T active(Boolean active) {
			claim(IntrospectionClaimNames.ACTIVE.value, active);
			return downcast();
		}

		public T audience(Stream<String> audience) {
			claim(IntrospectionClaimNames.AUDIENCE.value, audience.collect(Collectors.toSet()));
			return downcast();
		}

		public T audience(String... audience) {
			return audience(Stream.of(audience));
		}

		public T audience(Collection<String> audience) {
			return audience(audience.stream());
		}

		public T clientId(String clientId) {
			claim(IntrospectionClaimNames.CLIENT_ID.value, clientId);
			return downcast();
		}

		public T expirationTime(Instant expirationTime) {
			claim(IntrospectionClaimNames.EXPIRES_AT.value, expirationTime);
			return downcast();
		}

		public T expiresIn(long seconds) {
			claim(IntrospectionClaimNames.EXPIRES_AT.value, Instant.now().plus(Duration.ofSeconds(seconds)));
			return downcast();
		}

		public T issuedAt(Instant issuedAt) {
			claim(IntrospectionClaimNames.ISSUED_AT.value, issuedAt);
			return downcast();
		}

		public T issuer(String issuer) {
			claim(IntrospectionClaimNames.ISSUER.value, issuer);
			return downcast();
		}

		public T jwtId(String jwtId) {
			claim(IntrospectionClaimNames.JTI.value, jwtId);
			return downcast();
		}

		public T notBefore(Instant notBefore) {
			claim(IntrospectionClaimNames.NOT_BEFORE.value, notBefore);
			return downcast();
		}

		public T scopes(Stream<String> scope) {
			claim(IntrospectionClaimNames.SCOPE.value, scope.collect(Collectors.toSet()));
			return downcast();
		}

		public T scopes(String... scope) {
			return scopes(Stream.of(scope));
		}

		public T scopes(Collection<String> scope) {
			return scopes(scope.stream());
		}

		public T scope(String scope) {
			final Set<String> currentScopes = getAsStringSet(IntrospectionClaimNames.SCOPE.value);
			if(currentScopes == null) {
				return this.scopes(scope);
			}

			return this.scopes(Stream.concat(currentScopes.stream(), Stream.of(scope)));
		}

		public T subject(String subject) {
			claim(IntrospectionClaimNames.SUBJECT.value, subject);
			return downcast();
		}

		public T tokenType(TokenType tokenType) {
			claim(IntrospectionClaimNames.TOKEN_TYPE.value, tokenType.value);
			return downcast();
		}

		public T username(String username) {
			claim(IntrospectionClaimNames.USERNAME.value, username);
			return downcast();
		}

		public IntrospectionClaimSet build() {
			return build(this);
		}

		public IntrospectionClaimSet build(Map<String, Object> claims) {
			return new IntrospectionClaimSet(claims);
		}

		@SuppressWarnings("unchecked")
		protected T downcast() {
			return (T) this;
		}
	}
}
