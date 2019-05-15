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

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.c4soft.oauth2.ClaimAccessor;
import com.c4soft.oauth2.DelegatingMap;

/**
 * <p>As per https://tools.ietf.org/html/rfc7519#section-3, the JWT is a claim-set only.
 * JOSE headers are a separate object.</p>
 *
 * <p>Might be extended to add public or private claim accessors</p>
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class Jwt extends DelegatingMap<String, Object> implements ClaimAccessor {

	public Jwt(Map<String, Object> delegate) {
		super(delegate);
	}

	@Override
	public Map<String, Object> getClaims() {
		return super.getDelegate();
	}

	public String getIssuer() {
		return getClaimAsString(JwtRegisteredClaimNames.ISSUER.value);
	}

	public String getSubject() {
		return getClaimAsString(JwtRegisteredClaimNames.SUBJECT.value);
	}

	public Collection<String> getAudience() {
		return getClaimAsStringSet(JwtRegisteredClaimNames.AUDIENCE.value);
	}

	public Instant getExpirationTime() {
		return getClaimAsInstant(JwtRegisteredClaimNames.EXPIRATION_TIME.value);
	}

	public Instant getNotBefore() {
		return getClaimAsInstant(JwtRegisteredClaimNames.NOT_BEFORE.value);
	}

	public Instant getIssuedAt() {
		return getClaimAsInstant(JwtRegisteredClaimNames.ISSUED_AT.value);
	}

	public String getJwtId() {
		return getClaimAsString(JwtRegisteredClaimNames.JWT_ID.value);
	}

	public static Builder<?> builder() {
		return new Builder<>();
	}

	public static class Builder<T extends Builder<T>> {

		private final Map<String, Object> claimSet = new HashMap<>();

		public T claim(String name, Object value) {
			return setOrRemove(name, value);
		}

		public T issuer(String issuer) {
			return setOrRemove(JwtRegisteredClaimNames.ISSUER.value, issuer);
		}

		public T subject(String subject) {
			return setOrRemove(JwtRegisteredClaimNames.SUBJECT.value, subject);
		}

		public T audience(Stream<String> audience) {
			return setOrRemove(JwtRegisteredClaimNames.AUDIENCE.value, audience.collect(Collectors.toSet()));
		}

		public T audience(String... audience) {
			return audience(Stream.of(audience));
		}

		public T audience(Collection<String> audience) {
			return audience(audience.stream());
		}

		public T expirationTime(Instant expirationTime) {
			return setOrRemove(JwtRegisteredClaimNames.EXPIRATION_TIME.value, expirationTime);
		}

		public T expiresIn(long seconds) {
			return setOrRemove(JwtRegisteredClaimNames.EXPIRATION_TIME.value, Instant.now().plus(Duration.ofSeconds(seconds)));
		}

		public T notBefore(Instant notBefore) {
			return setOrRemove(JwtRegisteredClaimNames.NOT_BEFORE.value, notBefore);
		}

		public T issuedAt(Instant issuedAt) {
			return setOrRemove(JwtRegisteredClaimNames.ISSUED_AT.value, issuedAt);
		}

		public T jwtId(String jwtId) {
			return setOrRemove(JwtRegisteredClaimNames.JWT_ID.value, jwtId);
		}

		public Jwt build() {
			return new Jwt(claimSet);
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
