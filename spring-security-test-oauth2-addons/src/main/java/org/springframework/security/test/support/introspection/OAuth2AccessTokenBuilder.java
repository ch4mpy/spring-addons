package org.springframework.security.test.support.introspection;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.TokenAttributesStringListConverter;
import org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames;
import org.springframework.util.StringUtils;

public class OAuth2AccessTokenBuilder {

	private static final Converter<Map<String, Object>, List<String>> SCOPES_CONVERTER =
			TokenAttributesStringListConverter.builder()
			.scanedAttributes(OAuth2IntrospectionClaimNames.SCOPE)
			.elementsRegex(" ")
			.build();

	private String value;
	private final Map<String, Object> attributes;
	private final TokenAttributesAccessor attributesAccessor;

	public OAuth2AccessTokenBuilder(Map<String, Object> tokenAttributes) {
		this.attributes = tokenAttributes;
		this.attributesAccessor = new TokenAttributesAccessor(this.attributes);
	}

	public OAuth2AccessTokenBuilder value(String tokenValue) {
		this.value = tokenValue;
		return this;
	}

	public OAuth2AccessTokenBuilder issuedAt(Instant issuedAt) {
		this.attributes.put(OAuth2IntrospectionClaimNames.ISSUED_AT, issuedAt);
		return this;
	}

	public OAuth2AccessTokenBuilder expiresAt(Instant expiresAt) {
		this.attributes.put(OAuth2IntrospectionClaimNames.EXPIRES_AT, expiresAt);
		return this;
	}

	public OAuth2AccessTokenBuilder username(String name) {
		this.attributes.put(OAuth2IntrospectionClaimNames.USERNAME, name);
		return this;
	}

	public OAuth2AccessTokenBuilder subject(String subject) {
		this.attributes.put(OAuth2IntrospectionClaimNames.SUBJECT, subject);
		return this;
	}

	public OAuth2AccessTokenBuilder scope(String scope) {
		return scopes(Stream.concat(
				SCOPES_CONVERTER.convert(attributes).stream(),
				Stream.of(scope)));
	}

	public OAuth2AccessTokenBuilder scopes(Stream<String> scopes) {
		attributes.put(OAuth2IntrospectionClaimNames.SCOPE, scopes.collect(Collectors.joining(" ")));
		return this;
	}

	public OAuth2AccessTokenBuilder scopes(String... scopes) {
		return scopes(Stream.of(scopes));
	}

	public Collection<String> getScopes() {
		return SCOPES_CONVERTER.convert(attributes);
	}

	public boolean hasScope() {
		final String scope = attributesAccessor.getClaimAsString(OAuth2IntrospectionClaimNames.SCOPE);
		return StringUtils.hasLength(scope);
	}

	public boolean hasUsername() {
		return StringUtils.hasLength(attributesAccessor.getClaimAsString(OAuth2IntrospectionClaimNames.USERNAME));
	}

	public boolean hasSubject() {
		return StringUtils.hasLength(attributesAccessor.getClaimAsString(OAuth2IntrospectionClaimNames.SUBJECT));
	}

	public boolean hasValue() {
		return StringUtils.hasLength(value);
	}

	public OAuth2AccessToken build() {
		attributes.put(OAuth2IntrospectionClaimNames.TOKEN_TYPE, TokenType.BEARER.getValue());
		return new OAuth2AccessToken(
				TokenType.BEARER,
				value,
				attributesAccessor.getClaimAsInstant(OAuth2IntrospectionClaimNames.ISSUED_AT),
				attributesAccessor.getClaimAsInstant(OAuth2IntrospectionClaimNames.EXPIRES_AT),
				new HashSet<>(getScopes()));
	}

	public static class TokenAttributesAccessor implements ClaimAccessor {

		private final Map<String, Object> tokenAttributes;

		public TokenAttributesAccessor(Map<String, Object> tokenAttributes) {
			this.tokenAttributes = tokenAttributes;
		}

		@Override
		public Map<String, Object> getClaims() {
			return tokenAttributes;
		}

	}

}
