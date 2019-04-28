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
package org.springframework.security.test.support;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.server.resource.authentication.AttributesToStringCollectionToAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.StringCollectionAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.TokenAttributesStringListConverter;
import org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2LoginAuthenticationTokenBuilder extends AbstractOAuth2AuthenticationBuilder<OAuth2LoginAuthenticationTokenBuilder, Map<String, Object>> {
	public static final String DEFAULT_TOKEN_VALUE = "Open ID test";
	public static final String DEFAULT_NAME_ATTRIBUTE_KEY = IdTokenClaimNames.SUB;
	public static final String DEFAULT_REQUEST_REDIRECT_URI = "https://localhost:8080/";
	public static final String DEFAULT_REQUEST_AUTHORIZATION_URI = "https://localhost:8080/authorize";
	public static final String DEFAULT_REQUEST_GRANT_TYPE = "authorization_code";
	public static final String DEFAULT_CLIENT_TOKEN_URI = "https://localhost:8080/token";
	public static final String DEFAULT_CLIENT_ID = "mocked-client";
	public static final String DEFAULT_CLIENT_REGISTRATION_ID = "mocked-registration";
	public static final String DEFAULT_CLIENT_GRANT_TYPE = "client_credentials";

	private static final Converter<Map<String, Object>, List<String>> scopesConverter = TokenAttributesStringListConverter.builder().build();
	private static final Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter = new AttributesToStringCollectionToAuthoritiesConverter(
			scopesConverter,
			new StringCollectionAuthoritiesConverter("SCOPE_"));

	private final String tokenValue;
	private String nameAttributeName;
	private final ClientRegistrationBuilder clientRegistrationBuilder;
	private final AuthorizationRequestBuilder authorizationRequestBuilder;
	private final Map<String, Object> openIdClaims;

	public OAuth2LoginAuthenticationTokenBuilder(AuthorizationGrantType requestAuthorizationGrantType) {
		super(authoritiesConverter, DEFAULT_TOKEN_VALUE);
		this.tokenValue = DEFAULT_TOKEN_VALUE;
		this.nameAttributeName = DEFAULT_NAME_ATTRIBUTE_KEY;
		this.clientRegistrationBuilder = new ClientRegistrationBuilder();
		this.authorizationRequestBuilder = new AuthorizationRequestBuilder(requestAuthorizationGrantType, attributes);
		this.openIdClaims = new HashMap<>();
	}

	public OAuth2LoginAuthenticationTokenBuilder principal(OidcUser user) {
		final DefaultOAuth2User oauth2User = (DefaultOAuth2User)user;
		final Map<String, Object> openIdClaims = new HashMap<>(user.getAttributes());
		final OidcIdToken token = ((DefaultOidcUser) oauth2User).getIdToken();
		putIfNotEmpty(IdTokenClaimNames.IAT, token.getIssuedAt(), openIdClaims);
		putIfNotEmpty(IdTokenClaimNames.EXP, token.getExpiresAt(), openIdClaims);

		if(user instanceof DefaultOidcUser) {
			nameAttributeKey(reflectNameAttributeKey(oauth2User));
		}

		return openIdClaims(openIdClaims);
	}

	public OAuth2LoginAuthenticationTokenBuilder nameAttributeKey(String nameAttributeKey) {
		if(this.attributes.containsKey(nameAttributeName)) {
			this.attributes.put(nameAttributeKey, this.attributes.get(nameAttributeName));
		}
		this.attributes.remove(nameAttributeName);

		if(this.openIdClaims.containsKey(nameAttributeName)) {
			this.openIdClaims.put(nameAttributeKey, this.openIdClaims.get(nameAttributeName));
		}
		this.openIdClaims.remove(nameAttributeName);

		this.nameAttributeName = nameAttributeKey;
		return downCast();
	}

	public OAuth2LoginAuthenticationTokenBuilder openIdClaim(String name, Object value) {
		this.openIdClaims.put(name, value);
		return downCast();
	}

	public OAuth2LoginAuthenticationTokenBuilder openIdClaims(Map<String, Object> claims) {
		Assert.notNull(claims, "OpenID claims must be non null");
		this.openIdClaims.clear();
		claims.entrySet().stream().forEach(e -> this.openIdClaim(e.getKey(), e.getValue()));
		return downCast();
	}

	public String nameAttributeName(String nameAttributeName) {
		return this.nameAttributeName = nameAttributeName;
	}

	public ClientRegistrationBuilder getClientRegistrationBuilder() {
		return clientRegistrationBuilder;
	}

	public AuthorizationRequestBuilder getAuthorizationRequestBuilder() {
		return authorizationRequestBuilder;
	}

	public OAuth2LoginAuthenticationToken build() {
		Assert.hasLength(nameAttributeName, "nameAttributeName can't be empty");
		if(!attributes.containsKey(nameAttributeName)) {
			attributes.put(nameAttributeName, Defaults.AUTH_NAME);
		}
		if(!attributes.containsKey(OAuth2IntrospectionClaimNames.SCOPE)) {
			attributes.put(OAuth2IntrospectionClaimNames.SCOPE, Stream.of(Defaults.AUTHORITIES).collect(Collectors.joining(" ")));
		}
		if(!openIdClaims.containsKey(nameAttributeName)) {
			openIdClaims.put(nameAttributeName, Defaults.AUTH_NAME);
		}
		final OidcIdToken openIdToken = new OidcIdToken(
				tokenValue,
				(Instant) openIdClaims.get(IdTokenClaimNames.IAT),
				(Instant) openIdClaims.get(IdTokenClaimNames.EXP),
				openIdClaims);

		final Set<String> scopes = new HashSet<>(scopesConverter.convert(attributes));
		final Collection<GrantedAuthority> authorities = authoritiesConverter.convert(attributes);

		final OAuth2AccessToken accessToken = new OAuth2AccessToken(
				TokenType.BEARER,
				tokenValue,
				(Instant) attributes.get("iat"),
				(Instant) attributes.get("exp"),
				scopes);

		final ClientRegistration clientRegistration =
				clientRegistrationBuilder.scope(scopes).userNameAttributeName(nameAttributeName).build();

		final OAuth2AuthorizationRequest authorizationRequest =
				authorizationRequestBuilder.attributes(attributes).scopes(scopes).build();

		final String redirectUri = StringUtils.isEmpty(authorizationRequest.getRedirectUri()) ?
				clientRegistration.getRedirectUriTemplate() : authorizationRequest.getRedirectUri();

				final OAuth2AuthorizationExchange authorizationExchange =
						new OAuth2AuthorizationExchange(authorizationRequest, auth2AuthorizationResponse(redirectUri));

				final DefaultOidcUser principal = new DefaultOidcUser(authorities, openIdToken, nameAttributeName);

				return new OAuth2LoginAuthenticationToken(
						clientRegistration,
						authorizationExchange,
						principal,
						authorities,
						accessToken);
	}

	private static OAuth2AuthorizationResponse auth2AuthorizationResponse(String redirectUri) {
		final OAuth2AuthorizationResponse.Builder builder =
				OAuth2AuthorizationResponse.success("test-authorization-success-code");
		builder.redirectUri(redirectUri);
		return builder.build();
	}

	private static String reflectNameAttributeKey(DefaultOAuth2User user) {
		try {
			return (String)user.getClass().getDeclaredField("nameAttributeKey").get(user);
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static class ClientRegistrationBuilder {
		private final ClientRegistration.Builder delegate;

		public ClientRegistrationBuilder() {
			this.delegate = ClientRegistration.withRegistrationId(DEFAULT_CLIENT_REGISTRATION_ID)
					.authorizationGrantType(new AuthorizationGrantType(DEFAULT_CLIENT_GRANT_TYPE))
					.clientId(DEFAULT_CLIENT_ID)
					.tokenUri(DEFAULT_CLIENT_TOKEN_URI);
		}

		public ClientRegistrationBuilder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
			delegate.authorizationGrantType(authorizationGrantType);
			return this;
		}

		public ClientRegistrationBuilder authorizationUri(String authorizationUri) {
			delegate.authorizationUri(authorizationUri);
			return this;
		}

		public ClientRegistrationBuilder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
			delegate.clientAuthenticationMethod(clientAuthenticationMethod);
			return this;
		}

		public ClientRegistrationBuilder clientId(String clientId) {
			delegate.clientId(clientId);
			return this;
		}

		public ClientRegistrationBuilder clientName(String clientName) {
			delegate.clientName(clientName);
			return this;
		}

		public ClientRegistrationBuilder clientSecret(String clientSecret) {
			delegate.clientSecret(clientSecret);
			return this;
		}

		public ClientRegistrationBuilder jwkSetUri(String jwkSetUri) {
			delegate.jwkSetUri(jwkSetUri);
			return this;
		}

		public ClientRegistrationBuilder providerConfigurationMetadata(Map<String, Object> configurationMetadata) {
			delegate.providerConfigurationMetadata(configurationMetadata);
			return this;
		}

		public ClientRegistrationBuilder redirectUriTemplate(String redirectUriTemplate) {
			delegate.redirectUriTemplate(redirectUriTemplate);
			return this;
		}

		public ClientRegistrationBuilder registrationId(String registrationId) {
			delegate.registrationId(registrationId);
			return this;
		}

		ClientRegistrationBuilder scope(String... scopes) {
			delegate.scope(scopes);
			return this;
		}

		ClientRegistrationBuilder scope(Collection<String> scopes) {
			delegate.scope(scopes);
			return this;
		}

		public ClientRegistrationBuilder tokenUri(String tokenUri) {
			delegate.tokenUri(tokenUri);
			return this;
		}

		public ClientRegistrationBuilder userInfoAuthenticationMethod(AuthenticationMethod userInfoAuthenticationMethod) {
			delegate.userInfoAuthenticationMethod(userInfoAuthenticationMethod);
			return this;
		}

		public ClientRegistrationBuilder userInfoUri(String userInfoUri) {
			delegate.userInfoUri(userInfoUri);
			return this;
		}

		public ClientRegistrationBuilder userNameAttributeName(String nameAttributeName) {
			delegate.userNameAttributeName(nameAttributeName);
			return this;
		}

		public ClientRegistration build() {
			return delegate.build();
		}
	}

	public static class AuthorizationRequestBuilder {
		private final OAuth2AuthorizationRequest.Builder delegate;
		private final Map<String, Object> additionalParameters;

		public AuthorizationRequestBuilder(
				final AuthorizationGrantType authorizationGrantType,
				final Map<String, Object> additionalParameters) {
			this.additionalParameters = additionalParameters;
			this.delegate = authorizationRequestBuilder(authorizationGrantType)
					.authorizationUri(DEFAULT_REQUEST_AUTHORIZATION_URI)
					.clientId(DEFAULT_CLIENT_ID)
					.redirectUri(DEFAULT_REQUEST_REDIRECT_URI)
					.additionalParameters(additionalParameters);
		}

		public AuthorizationRequestBuilder additionalParameter(String name, Object value) {
			additionalParameters.put(name, value);
			return this;
		}

		AuthorizationRequestBuilder attributes(Map<String, Object> attributes) {
			delegate.attributes(attributes);
			return this;
		}

		public AuthorizationRequestBuilder authorizationRequestUri(String authorizationRequestUri) {
			delegate.authorizationRequestUri(authorizationRequestUri);
			return this;
		}

		public AuthorizationRequestBuilder authorizationUri(String authorizationUri) {
			delegate.authorizationUri(authorizationUri);
			return this;
		}

		public AuthorizationRequestBuilder clientId(String clientId) {
			delegate.clientId(clientId);
			return this;
		}

		public AuthorizationRequestBuilder redirectUri(String redirectUri) {
			delegate.redirectUri(redirectUri);
			return this;
		}

		public AuthorizationRequestBuilder state(String state) {
			delegate.state(state);
			return this;
		}

		AuthorizationRequestBuilder scope(String... scopes) {
			delegate.scope(scopes);
			return this;
		}

		AuthorizationRequestBuilder scopes(Set<String> scopes) {
			delegate.scopes(scopes);
			return this;
		}

		public OAuth2AuthorizationRequest build() {
			return delegate.build();
		}

		private static OAuth2AuthorizationRequest.Builder authorizationRequestBuilder(AuthorizationGrantType authorizationGrantType) {
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
				return OAuth2AuthorizationRequest.authorizationCode();
			}
			if (AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType)) {
				return OAuth2AuthorizationRequest.implicit();
			}
			throw new UnsupportedOperationException(
					"Only authorization_code and implicit grant types are supported for MockOAuth2AuthorizationRequest");
		}
	}

}
