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
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.c4soft.oauth2.ClaimAccessor;
import com.c4soft.oauth2.DelegatingMap;
import com.c4soft.oauth2.rfc6749.TokenType;

/**
 * <p>As per https://tools.ietf.org/html/rfc7519#section-3, the JWT is a claim-set only.
 * JOSE headers are a separate object.</p>
 *
 * <p>Might be extended to add public or private claim accessors</p>
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class IntrospectionToken extends DelegatingMap<String, Object> implements ClaimAccessor {

	public IntrospectionToken(Map<String, Object> delegate) {
		super(delegate);
	}

	@Override
	public Map<String, Object> getClaims() {
		return super.getDelegate();
	}

	public Boolean getActive() {
		return getClaimAsBoolean(IntrospectionClaimNames.ACTIVE.value);
	}

	public Collection<String> getAudience() {
		return getClaimAsStringSet(IntrospectionClaimNames.AUDIENCE.value);
	}

	public String getClientId() {
		return getClaimAsString(IntrospectionClaimNames.CLIENT_ID.value);
	}

	public Instant getExpiresAt() {
		return getClaimAsInstant(IntrospectionClaimNames.EXPIRES_AT.value);
	}

	public Instant getIssuedAt() {
		return getClaimAsInstant(IntrospectionClaimNames.ISSUED_AT.value);
	}

	public URI getIssuer() throws URISyntaxException {
		return getClaimAsUri(IntrospectionClaimNames.ISSUER.value);
	}

	public String getJti() {
		return getClaimAsString(IntrospectionClaimNames.JTI.value);
	}

	public Instant getNotBefore() {
		return getClaimAsInstant(IntrospectionClaimNames.NOT_BEFORE.value);
	}

	public Set<String> getScope() {
		return getClaimAsStringSet(IntrospectionClaimNames.SCOPE.value);
	}

	public String getSubject() {
		return getClaimAsString(IntrospectionClaimNames.SUBJECT.value);
	}

	public TokenType getTokenType() {
		final String str = getClaimAsString(IntrospectionClaimNames.TOKEN_TYPE.value);
		if(str == null) {
			return null;
		}
		return TokenType.valueOf(str);
	}

	public String getUsername() {
		return getClaimAsString(IntrospectionClaimNames.USERNAME.value);
	}

	public static Builder<?> builder() {
		return new Builder<>();
	}

	public static class Builder<T extends Builder<T>> {

		private final Map<String, Object> claimSet = new HashMap<>();

		public T claim(String name, Object value) {
			return setOrRemove(name, value);
		}

		public T active(Boolean active) {
			return setOrRemove(IntrospectionClaimNames.ACTIVE.value, active);
		}

		public T audience(Stream<String> audience) {
			return setOrRemove(IntrospectionClaimNames.AUDIENCE.value, audience.collect(Collectors.toSet()));
		}

		public T audience(String... audience) {
			return audience(Stream.of(audience));
		}

		public T audience(Collection<String> audience) {
			return audience(audience.stream());
		}

		public T clientId(String clientId) {
			return setOrRemove(IntrospectionClaimNames.CLIENT_ID.value, clientId);
		}

		public T expirationTime(Instant expirationTime) {
			return setOrRemove(IntrospectionClaimNames.EXPIRES_AT.value, expirationTime);
		}

		public T expiresIn(long seconds) {
			return setOrRemove(IntrospectionClaimNames.EXPIRES_AT.value, Instant.now().plus(Duration.ofSeconds(seconds)));
		}

		public T issuedAt(Instant issuedAt) {
			return setOrRemove(IntrospectionClaimNames.ISSUED_AT.value, issuedAt);
		}

		public T issuer(String issuer) {
			return setOrRemove(IntrospectionClaimNames.ISSUER.value, issuer);
		}

		public T jwtId(String jwtId) {
			return setOrRemove(IntrospectionClaimNames.JTI.value, jwtId);
		}

		public T notBefore(Instant notBefore) {
			return setOrRemove(IntrospectionClaimNames.NOT_BEFORE.value, notBefore);
		}

		public T scope(Stream<String> scope) {
			return setOrRemove(IntrospectionClaimNames.SCOPE.value, scope.collect(Collectors.toSet()));
		}

		public T scope(String... scope) {
			return scope(Stream.of(scope));
		}

		public T scope(Collection<String> scope) {
			return scope(scope.stream());
		}

		public T subject(String subject) {
			return setOrRemove(IntrospectionClaimNames.SUBJECT.value, subject);
		}

		public T tokenType(TokenType tokenType) {
			return setOrRemove(IntrospectionClaimNames.TOKEN_TYPE.value, tokenType.value);
		}

		public T username(String username) {
			return setOrRemove(IntrospectionClaimNames.USERNAME.value, username);
		}

		public IntrospectionToken build() {
			return new IntrospectionToken(claimSet);
		}

		@SuppressWarnings("unchecked")
		protected T downcast() {
			return (T) this;
		}

		private T setOrRemove(String claimName, String claimValue) {
			Assert.hasLength(claimName, "claimName can't be empty");
			if(StringUtils.hasLength(claimValue)) {
				this.claimSet.put(claimName, claimValue);
			} else {
				this.claimSet.remove(claimName);
			}
			return downcast();
		}

		private T setOrRemove(String claimName, Collection<?> claimValue) {
			Assert.hasLength(claimName, "claimName can't be empty");
			if(claimValue == null || claimValue.isEmpty()) {
				this.claimSet.remove(claimName);
			} else {
				this.claimSet.put(claimName, claimValue);
			}
			return downcast();
		}

		private T setOrRemove(String claimName, Object claimValue) {
			Assert.hasLength(claimName, "claimName can't be empty");
			if(claimValue == null) {
				this.claimSet.remove(claimName);
			} else {
				this.claimSet.put(claimName, claimValue);
			}
			return downcast();
		}
	}
}
