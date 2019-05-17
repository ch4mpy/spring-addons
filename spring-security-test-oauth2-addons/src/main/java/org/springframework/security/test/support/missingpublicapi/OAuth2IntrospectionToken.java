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
package org.springframework.security.test.support.missingpublicapi;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class OAuth2IntrospectionToken {

	private final String value;
	private final TokenProperties attributes;

	public OAuth2IntrospectionToken(String value, Map<String, Object> attributes) {
		super();
		this.value = value;
		this.attributes = new TokenProperties(Collections.unmodifiableMap(attributes));
	}

	public TokenProperties getAttributes() {
		return attributes;
	}

	public String getValue() {
		return value;
	}

	public Boolean isActive() {
		return attributes.getClaimAsBoolean(OAuth2IntrospectionClaimNames.ACTIVE);
	}

	public Set<String> getAudience() {
		final Object claim = attributes.getClaims().get(OAuth2IntrospectionClaimNames.AUDIENCE);
		if(claim == null) {
			return Collections.emptySet();
		}
		if(claim instanceof Collection) {
			return ((Collection<?>) claim).stream().map(Object::toString).collect(Collectors.toSet());
		}
		return Stream.of(claim.toString().split(" ")).collect(Collectors.toSet());
	}

	public String getClientId() {
		return attributes.getClaimAsString(OAuth2IntrospectionClaimNames.CLIENT_ID);
	}

	public Instant getExpiresAt() {
		return attributes.getClaimAsInstant(OAuth2IntrospectionClaimNames.EXPIRES_AT);
	}

	public Instant getIssuedAt() {
		return attributes.getClaimAsInstant(OAuth2IntrospectionClaimNames.ISSUED_AT);
	}

	public String getIssuer() {
		return attributes.getClaimAsString(OAuth2IntrospectionClaimNames.ISSUER);
	}

	public String getJti() {
		return attributes.getClaimAsString(OAuth2IntrospectionClaimNames.JTI);
	}

	public Instant getNotBefore() {
		return attributes.getClaimAsInstant(OAuth2IntrospectionClaimNames.NOT_BEFORE);
	}

	public OAuth2Scopes getScope() {
		return OAuth2Scopes.from(attributes);
	}

	public String getSubject() {
		return attributes.getClaimAsString(OAuth2IntrospectionClaimNames.SUBJECT);
	}

	public TokenType getTokenType() {
		final String claim = attributes.getClaimAsString(OAuth2IntrospectionClaimNames.TOKEN_TYPE);
		if(claim == null) {
			return null;
		}
		switch(claim.toLowerCase()) {
		case "bearer": return TokenType.BEARER;
		}
		throw new RuntimeException("unsupported token-type: \"" + claim + "\"");
	}

	public String getUsername() {
		return attributes.getClaimAsString(OAuth2IntrospectionClaimNames.USERNAME);
	}

	public static OAuth2IntrospectionTokenBuilder<?> builder() {
		return new OAuth2IntrospectionTokenBuilder<>();
	}

	/**
	 *
	 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
	 *
	 * @param <T> capture for extending class type
	 */
	public static class OAuth2IntrospectionTokenBuilder<T extends OAuth2IntrospectionTokenBuilder<T>> {

		private String value;
		private final TokenProperties attributes;

		public OAuth2IntrospectionTokenBuilder(Map<String, Object> tokenAttributes) {
			this.attributes = new TokenProperties(tokenAttributes);
		}

		public OAuth2IntrospectionTokenBuilder() {
			this.attributes = new TokenProperties();
		}

		/**
		 *
		 * add an attribute if value not null, removes it otherwise
		 * @param name attribute name
		 * @param value attribute value
		 * @return this builder to further configure
		 */
		public T attribute(String name, Object value) {
			if (value == null) {
				this.attributes.remove(name);
			} else {
				this.attributes.put(name, value);
			}
			return downcast();
		}

		/**
		 * Replaces all attributes (clears first, does not add to existing ones)
		 * @param tokenAttributes new token attributes set
		 * @return this builder to further configure
		 */
		public T attributes(Map<String, Object> tokenAttributes) {
			this.attributes.clear();
			this.attributes.putAll(tokenAttributes);
			return downcast();
		}

		public T active(Boolean active) {
			this.attribute(OAuth2IntrospectionClaimNames.ISSUED_AT, active);
			return downcast();
		}

		public T audience(Stream<String> audience) {
			this.attribute(OAuth2IntrospectionClaimNames.AUDIENCE, audience.collect(Collectors.joining(" ")));
			return downcast();
		}

		public T audience(String... audience) {
			return audience(Stream.of(audience));
		}

		public T clientId(String clientId) {
			this.attribute(OAuth2IntrospectionClaimNames.CLIENT_ID, clientId);
			return downcast();
		}

		public T expiresAt(Instant expiresAt) {
			this.attribute(OAuth2IntrospectionClaimNames.EXPIRES_AT, expiresAt);
			return downcast();
		}

		public T issuedAt(Instant issuedAt) {
			this.attribute(OAuth2IntrospectionClaimNames.ISSUED_AT, issuedAt);
			return downcast();
		}

		public T issuer(String issuer) {
			this.attribute(OAuth2IntrospectionClaimNames.ISSUER, issuer);
			return downcast();
		}

		public T jti(String jti) {
			this.attribute(OAuth2IntrospectionClaimNames.JTI, jti);
			return downcast();
		}

		public T notBefore(Instant notBefore) {
			this.attribute(OAuth2IntrospectionClaimNames.NOT_BEFORE, notBefore);
			return downcast();
		}

		public T scope(String scope) {
			return scopes(
					Stream.concat(
							OAuth2Scopes.from(attributes).stream(),
							Stream.of(scope)));
		}

		public T scopes(Stream<String> scopes) {
			new OAuth2Scopes(scopes.collect(Collectors.toSet())).putIn(attributes);
			return downcast();
		}

		public T scopes(String... scopes) {
			return scopes(Stream.of(scopes));
		}

		public T subject(String subject) {
			this.attribute(OAuth2IntrospectionClaimNames.SUBJECT, subject);
			return downcast();
		}

		public T tokenType(TokenType tokenType) {
			this.attribute(OAuth2IntrospectionClaimNames.TOKEN_TYPE, tokenType.getValue().toLowerCase());
			return downcast();
		}

		public T username(String username) {
			this.attribute(OAuth2IntrospectionClaimNames.USERNAME, username);
			return downcast();
		}

		public T value(String tokenValue) {
			this.value = tokenValue;
			return downcast();
		}

		public OAuth2IntrospectionToken build() {
			return new OAuth2IntrospectionToken(value, attributes);
		}

		protected Collection<String> getScopes() {
			return OAuth2Scopes.from(attributes);
		}

		@SuppressWarnings("unchecked")
		protected T downcast() {
			return (T) this;
		}
	}
}
