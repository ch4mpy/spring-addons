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
package com.c4soft.springaddons.security.test.support.openid;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.c4soft.springaddons.security.test.support.AuthenticationBuilder;
import com.c4soft.springaddons.security.test.support.Defaults;
import com.c4soft.springaddons.security.test.support.introspection.OAuth2IntrospectionTokenTestingBuilder;
import com.c4soft.springaddons.security.test.support.missingpublicapi.AuthorizationRequestBuilder;
import com.c4soft.springaddons.security.test.support.missingpublicapi.ClientRegistrationBuilder;
import com.c4soft.springaddons.security.test.support.missingpublicapi.DefaultOidcUserBuilder;
import com.c4soft.springaddons.security.test.support.missingpublicapi.IdTokenBuilder;
import com.c4soft.springaddons.security.test.support.missingpublicapi.OAuth2IntrospectionToken;
import com.c4soft.springaddons.security.test.support.missingpublicapi.OAuth2IntrospectionToken.OAuth2IntrospectionTokenBuilder;

/**
 * Builder with test default values for {@link OAuth2LoginAuthenticationToken}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 * @param <T> capture for extending class type
 */
public class OAuth2LoginAuthenticationTokenTestingBuilder<T extends OAuth2LoginAuthenticationTokenTestingBuilder<T>> implements AuthenticationBuilder<OAuth2LoginAuthenticationToken>{
	private static final String AUTHORITIES_PREFIX = "SCOPE_";

	private static final Converter<Collection<String>, Collection<GrantedAuthority>> authoritiesConverter =scopes -> scopes.stream()
			.map(s -> new SimpleGrantedAuthority(AUTHORITIES_PREFIX + s))
			.collect(Collectors.toSet());

	public static final URI DEFAULT_ISSUER = defaultIssuer();
	public static final String DEFAULT_NAME_ATTRIBUTE_KEY = StandardClaimNames.NAME;
	public static final String DEFAULT_REQUEST_REDIRECT_URI = "https://localhost:8080/";
	public static final String DEFAULT_AUTHORIZATION_URI = "https://localhost:8080/authorize";
	public static final String DEFAULT_REQUEST_GRANT_TYPE = "implicit";
	public static final String DEFAULT_REQUEST_STATE = "test-state";
	public static final String DEFAULT_TOKEN_URI = "https://localhost:8080/token";
	public static final String DEFAULT_CLIENT_ID = "mocked-client";
	public static final String DEFAULT_CLIENT_REGISTRATION_ID = "mocked-registration";
	public static final String DEFAULT_CLIENT_GRANT_TYPE = "client_credentials";

	private static final URI defaultIssuer() {
		try {
			return new URI("https://localhost:8042");
		} catch (final URISyntaxException e) {
			return null;
		}
	}

	private final IdTokenBuilder idToken;
	private final OAuth2IntrospectionTokenBuilder<?> accessTokenBuilder;
	private final DefaultOidcUserBuilder oidcUserBuilder;
	private final ClientRegistrationBuilder clientRegistrationBuilder;
	private final AuthorizationRequestBuilder authorizationRequestBuilder;

	public OAuth2LoginAuthenticationTokenTestingBuilder(AuthorizationGrantType requestAuthorizationGrantType) {
		try {
			final Instant now = Instant.now();
			this.idToken = new IdTokenBuilder()
					.value(Defaults.JWT_VALUE)
					.audience(DEFAULT_CLIENT_ID)
					.subject(Defaults.AUTH_NAME)
					.issuer(DEFAULT_ISSUER)
					.authenticatedAt(now)
					.issuedAt(now)
					.expiresAt(now.plus(Duration.ofDays(1)));
			this.accessTokenBuilder = new OAuth2IntrospectionTokenTestingBuilder();
			this.oidcUserBuilder = new DefaultOidcUserBuilder()
					.nameAttributeKey(DEFAULT_NAME_ATTRIBUTE_KEY);
			this.clientRegistrationBuilder = new ClientRegistrationBuilder(DEFAULT_CLIENT_REGISTRATION_ID)
					.authorizationGrantType(new AuthorizationGrantType(DEFAULT_CLIENT_GRANT_TYPE))
					.tokenUri(new URI(DEFAULT_TOKEN_URI))
					.authorizationUri(new URI(DEFAULT_AUTHORIZATION_URI));
			this.authorizationRequestBuilder = new AuthorizationRequestBuilder(requestAuthorizationGrantType)
					.redirectUri(new URI(DEFAULT_REQUEST_REDIRECT_URI))
					.authorizationUri(new URI(DEFAULT_AUTHORIZATION_URI))
					.state(DEFAULT_REQUEST_STATE);
			clientId(DEFAULT_CLIENT_ID);
			name(Defaults.AUTH_NAME);
		} catch (final URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}

	public OAuth2LoginAuthenticationTokenTestingBuilder() {
		this(new AuthorizationGrantType(DEFAULT_REQUEST_GRANT_TYPE));
	}

	public T idTokenValue(String value) {
		this.idToken.value(value);
		return downcast();
	}

	public T accessTokenValue(String value) {
		this.accessTokenBuilder.value(value);
		return downcast();
	}

	public T accessTokenIssuedAt(Instant issuedAt) {
		this.accessTokenBuilder.attributes(claims -> claims.issuedAt(issuedAt));
		return downcast();
	}

	public T accessTokenExpiresAt(Instant expiresAt) {
		this.accessTokenBuilder.attributes(claims -> claims.expirationTime(expiresAt));
		return downcast();
	}

	public T idTokenIssuedAt(Instant issuedAt) {
		this.idToken.issuedAt(issuedAt);
		return downcast();
	}

	public T idTokenExpiresAt(Instant expiresAt) {
		this.idToken.expiresAt(expiresAt);
		return downcast();
	}

	public T subject(String subject) {
		idToken.subject(subject);
		accessTokenBuilder.attributes(claims -> claims.subject(subject));
		return downcast();
	}

	public T nameAttributeKey(String nameAttributeKey) {
		oidcUserBuilder.nameAttributeKey(nameAttributeKey);
		return downcast();
	}

	public T name(String name) {
		oidcUserBuilder.name(name);
		accessTokenBuilder.attributes(claims -> claims.username(name));
		return downcast();
	}

	/**
	 * Add a claim to user info
	 * @param name preferably one of {@link StandardClaimNames} but can be anything
	 * @param value claim value
	 * @return this builder to further configure
	 */
	public T userInfoClaim(String name, Object value) {
		oidcUserBuilder.userInfo(name, value);
		return downcast();
	}

	/**
	 * <p>Add a claim to the ID-token. This claim can be one of {@link IdTokenClaimNames},
	 * {@link StandardClaimNames} (refer <a href="https://openid.net/specs/openid-connect-core-1_0.html#id_tokenExample">to the spec</a> for a sample) or about anything.</p>
	 * <p>If the claim name is one of {@link StandardClaimNames}, then the claim is added to user-info too.</p>
	 * @param name claim name
	 * @param value claims value
	 * @return this builder to further configure
	 */
	public T idTokenClaim(String name, Object value) {
		idToken.claim(name, value);
		if(DefaultOidcUserBuilder.OPENID_STANDARD_CLAIM_NAMES.contains(name)) {
			userInfoClaim(name, value);
		}
		return downcast();
	}

	/**
	 * You need this only for Spring "{@link GrantedAuthority}" scopes.<br>
	 * OpenID scopes are retrieved from ID-token and user-info claim-sets.
	 * @param scope a scope to turn into a {@link GrantedAuthority}
	 * @return this builder to further configure
	 */
	public T scope(String nonOpenIdScope) {
		Assert.isTrue(!DefaultOidcUserBuilder.OPENID_STANDARD_CLAIM_NAMES.contains(nonOpenIdScope),
				"scope must not be one of OpenID standard claim names which are retrieved from user-info and ID-token claim-sets to enforce consistency.");
		accessTokenBuilder.attributes(claims -> claims.scope(nonOpenIdScope));
		return downcast();
	}
	public T scopes(String... nonOpenIdScopes) {
		Assert.isTrue(Stream.of(nonOpenIdScopes).noneMatch(s -> DefaultOidcUserBuilder.OPENID_STANDARD_CLAIM_NAMES.contains(s)),
				"scope must not be one of OpenID standard claim names which are retrieved from user-info and ID-token claim-sets to enforce consistency.");
		accessTokenBuilder.attributes(claims -> claims.scopes(nonOpenIdScopes));
		return downcast();
	}

	@Override
	public OAuth2LoginAuthenticationToken build() {
		Assert.hasLength(oidcUserBuilder.getNameAttributeKey(), "nameAttributeName can't be empty");
		final var openIdToken = idToken.build();

		getOpenidScopes(openIdToken).forEach(scope -> accessTokenBuilder.attributes(claims -> claims.scope(scope)));
		accessTokenBuilder.attributes(claims -> claims.scope("openid"));

		final OAuth2IntrospectionToken introspectionToken = accessTokenBuilder.build();
		final OAuth2AccessToken accessToken = new OAuth2AccessToken(
				TokenType.BEARER,
				introspectionToken.getTokenValue(),
				introspectionToken.getAttributes().getIssuedAt(),
				introspectionToken.getAttributes().getExpiresAt(),
				introspectionToken.getAttributes().getScope());
		final Collection<GrantedAuthority> authorities = authoritiesConverter.convert(accessToken.getScopes());

		final ClientRegistration clientRegistration = clientRegistrationBuilder
				.scope(introspectionToken.getAttributes().getScope())
				.userNameAttributeName(oidcUserBuilder.getNameAttributeKey())
				.build();

		final OAuth2AuthorizationRequest authorizationRequest = authorizationRequestBuilder
				.scopes(introspectionToken.getAttributes().getScope())
				.build(introspectionToken.getAttributes());

		final String redirectUri = StringUtils.hasLength(authorizationRequest.getRedirectUri()) ? authorizationRequest.getRedirectUri()
				: clientRegistration.getRedirectUriTemplate();

		final OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, auth2AuthorizationResponse(redirectUri));

		return new OAuth2LoginAuthenticationToken(
				clientRegistration,
				authorizationExchange,
				oidcUserBuilder.build(authorities, openIdToken),
				authorities,
				accessToken);
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}

	private static OAuth2AuthorizationResponse auth2AuthorizationResponse(String redirectUri) {
		final OAuth2AuthorizationResponse.Builder builder =
				OAuth2AuthorizationResponse.success("test-authorization-success-code");
		builder.redirectUri(redirectUri);
		return builder.build();
	}

	public T requestUri(URI authorizationRequestUri) {
		authorizationRequestBuilder.requestUri(authorizationRequestUri);
		return downcast();
	}

	public T authorizationUri(URI authorizationUri) {
		clientRegistrationBuilder.authorizationUri(authorizationUri);
		authorizationRequestBuilder.authorizationUri(authorizationUri);
		return downcast();
	}

	public T clientId(String clientId) {
		clientRegistrationBuilder.clientId(clientId);
		authorizationRequestBuilder.clientId(clientId);
		return downcast();
	}

	public T redirectUri(URI redirectUri) {
		authorizationRequestBuilder.redirectUri(redirectUri);
		return downcast();
	}

	public T requestState(String state) {
		authorizationRequestBuilder.state(state);
		return downcast();
	}

	public T clientAuthorizationGrantType(AuthorizationGrantType authorizationGrantType) {
		clientRegistrationBuilder.authorizationGrantType(authorizationGrantType);
		return downcast();
	}

	public T clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
		clientRegistrationBuilder.clientAuthenticationMethod(clientAuthenticationMethod);
		return downcast();
	}

	public T clientName(String clientName) {
		clientRegistrationBuilder.clientName(clientName);
		return downcast();
	}

	public T clientSecret(String clientSecret) {
		clientRegistrationBuilder.clientSecret(clientSecret);
		return downcast();
	}

	public T jwkSetUri(URI jwkSetUri) {
		clientRegistrationBuilder.jwkSetUri(jwkSetUri);
		return downcast();
	}

	public T providerConfigurationMetadata(Map<String, Object> configurationMetadata) {
		clientRegistrationBuilder.providerConfigurationMetadata(configurationMetadata);
		return downcast();
	}

	public T clientRedirectUriTemplate(String redirectUriTemplate) {
		clientRegistrationBuilder.redirectUriTemplate(redirectUriTemplate);
		return downcast();
	}

	public T registrationId(String registrationId) {
		clientRegistrationBuilder.registrationId(registrationId);
		return downcast();
	}

	public T tokenUri(URI tokenUri) {
		clientRegistrationBuilder.tokenUri(tokenUri);
		return downcast();
	}

	public T userInfoAuthenticationMethod(AuthenticationMethod userInfoAuthenticationMethod) {
		clientRegistrationBuilder.userInfoAuthenticationMethod(userInfoAuthenticationMethod);
		return downcast();
	}

	public T userInfoUri(URI userInfoUri) {
		clientRegistrationBuilder.userInfoUri(userInfoUri);
		return downcast();
	}

	private static final Set<String> ID_TOKEN_CLAIMS;

	static {
		final var idTokenClaimNames = new IdTokenClaimNames() {};
		ID_TOKEN_CLAIMS = Stream.of(IdTokenClaimNames.class.getDeclaredFields()).map(f -> {
			try {
				return f.get(idTokenClaimNames).toString();
			} catch (IllegalArgumentException | IllegalAccessException e) {
				throw new RuntimeException(e);
			}
		}).collect(Collectors.toSet());
	}

	public Set<String> getOpenidScopes(OidcIdToken openIdToken) {
		return openIdToken.getClaims().keySet().stream()
				.filter(DefaultOidcUserBuilder.OPENID_STANDARD_CLAIM_NAMES::contains)
				.filter(name -> !ID_TOKEN_CLAIMS.contains(name))
				.collect(Collectors.toSet());
	}
}
