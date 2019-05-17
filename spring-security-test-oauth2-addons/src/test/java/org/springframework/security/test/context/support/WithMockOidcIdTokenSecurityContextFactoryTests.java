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
package org.springframework.security.test.context.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.security.test.context.support.StringAttribute.BooleanParser;
import org.springframework.security.test.context.support.StringAttribute.StringListParser;
import org.springframework.security.test.context.support.StringAttribute.UrlParser;
import org.springframework.security.test.context.support.WithMockOidcIdToken.Factory;
import org.springframework.security.test.support.Defaults;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class WithMockOidcIdTokenSecurityContextFactoryTests {

	private Factory factory;

	@Before
	public void setup() {
		factory = new Factory();
	}

	@WithMockOidcIdToken
	private static class Default {
	}

	@WithMockOidcIdToken(@StringAttribute(name = StandardClaimNames.EMAIL, value = "test@c4-soft.com"))
	private static class CustomMini {
	}

	@WithMockOidcIdToken(
			subject = "SomeId",
			name = "Some One",
			nonOpenIdScopes = { "a", "b" })
	private static class CustomFrequent {
	}

	@WithMockOidcIdToken(
			subject = "SomeId",
			nameAttributeKey = "nameTestKey",
			name = "truc",
			nonOpenIdScopes = { "a", "b" },
			clientId = "test-client",
			idTokenClaims = {
					@StringAttribute(name = IdTokenClaimNames.AUD, value = "test-client", parser = StringListParser.class),
					@StringAttribute(name = IdTokenClaimNames.AUD, value = "other-client", parser = StringListParser.class),
					@StringAttribute(name = IdTokenClaimNames.ISS, value = "https://test-issuer.org", parser = UrlParser.class),
					@StringAttribute(name = StandardClaimNames.EMAIL, value = "truc@c4-soft.com"),
					@StringAttribute(name = "private-id-token-claim", value = "test-value") },
			userInfoClaims = {
					@StringAttribute(name = StandardClaimNames.EMAIL_VERIFIED, value = "true", parser = BooleanParser.class),
					@StringAttribute(name = "private-user-info-claim", value = "test-value")},
			requestGrantType = "implicit",
			requestUri = "https://localhost:8080/authorize",
			redirectUri = "https://localhost:8080/",
			clientGrantType = "implicit",
			registrationId = "implicit-test-client-registration",
			tokenUri = "https://localhost:8080/token",
			authorizationUri = "https://localhost:8080/authorize")
	private static class CustomFull {
	}

	@Test
	public void defaults() {
		final OAuth2LoginAuthenticationToken auth = (OAuth2LoginAuthenticationToken) factory
				.createSecurityContext(AnnotationUtils.findAnnotation(Default.class, WithMockOidcIdToken.class))
				.getAuthentication();

		final OAuth2AccessToken accessToken = auth.getAccessToken();
		assertThat(accessToken.getExpiresAt()).isNotNull();
		assertThat(accessToken.getIssuedAt()).isNotNull();
		assertThat(accessToken.getScopes()).containsExactlyInAnyOrder("openid");
		assertThat(accessToken.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(accessToken.getTokenValue()).isEqualTo(Defaults.BEARER_TOKEN_VALUE);

		assertThat(auth.getAuthorities()).containsExactlyInAnyOrder(new SimpleGrantedAuthority("SCOPE_openid"));

		final OAuth2AuthorizationRequest authorizationRequest =
				auth.getAuthorizationExchange().getAuthorizationRequest();
		assertThat(authorizationRequest.getAttributes()).hasSize(6);
		assertThat(authorizationRequest.getAttributes().get(OAuth2IntrospectionClaimNames.SUBJECT)).isEqualTo("testuserid");
		assertThat(authorizationRequest.getAttributes().get(OAuth2IntrospectionClaimNames.USERNAME)).isEqualTo("user");
		assertThat(authorizationRequest.getAttributes().get(OAuth2IntrospectionClaimNames.ISSUED_AT)).isNotNull();
		assertThat(authorizationRequest.getAttributes().get(OAuth2IntrospectionClaimNames.EXPIRES_AT)).isNotNull();
		assertThat(authorizationRequest.getAttributes().get(OAuth2IntrospectionClaimNames.TOKEN_TYPE)).isEqualTo("bearer");
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo("https://localhost:8080/authorize");
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo("https://localhost:8080/authorize");
		assertThat(authorizationRequest.getClientId()).isEqualTo("mocked-client");
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.IMPLICIT);
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo("https://localhost:8080/");
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.TOKEN);
		assertThat(authorizationRequest.getScopes()).containsExactlyInAnyOrder("openid");

		final OAuth2AuthorizationResponse authorizationResponse =
				auth.getAuthorizationExchange().getAuthorizationResponse();
		assertThat(authorizationResponse.getCode()).isEqualTo("test-authorization-success-code");
		assertThat(authorizationResponse.getError()).isNull();
		assertThat(authorizationResponse.getRedirectUri()).isEqualTo("https://localhost:8080/");

		final ClientRegistration clientRegistration = auth.getClientRegistration();
		assertThat(clientRegistration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(clientRegistration.getClientAuthenticationMethod().getValue()).isEqualTo("basic");
		assertThat(clientRegistration.getClientId()).isEqualTo("mocked-client");
		assertThat(clientRegistration.getClientName()).isEqualTo("mocked-registration");
		assertThat(clientRegistration.getClientSecret()).isEqualTo("");
		assertThat(clientRegistration.getProviderDetails()).isNotNull();
		assertThat(clientRegistration.getRedirectUriTemplate()).isEqualTo("https://localhost:8080/");
		assertThat(clientRegistration.getRegistrationId()).isEqualTo("mocked-registration");
		assertThat(clientRegistration.getScopes()).containsExactlyInAnyOrder("openid");

		assertThat(auth.getCredentials()).isEqualTo("");

		assertThat(auth.getDetails()).isNull();

		assertThat(auth.getName()).isEqualTo(Defaults.AUTH_NAME);

		assertThat(auth.getPrincipal()).isInstanceOf(DefaultOidcUser.class);
		final DefaultOidcUser principal = (DefaultOidcUser) auth.getPrincipal();
		assertThat(principal.getSubject()).isEqualTo(Defaults.SUBJECT);
		assertThat(principal.getName()).isEqualTo(Defaults.AUTH_NAME);
		assertThat(principal.getClaims()).hasSize(7);
		assertThat(principal.getAuthorities()).hasSize(1);
		assertThat(principal.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_openid"))).isTrue();

		assertThat(auth.getRefreshToken()).isNull();
	}

	@Test
	public void customMini() {
		final OAuth2LoginAuthenticationToken auth = (OAuth2LoginAuthenticationToken) factory
				.createSecurityContext(AnnotationUtils.findAnnotation(CustomMini.class, WithMockOidcIdToken.class))
				.getAuthentication();

		assertThat(auth.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("SCOPE_openid"));

		assertThat(auth.getPrincipal().getAuthorities()).hasSize(1);
		assertThat(auth.getPrincipal().getAuthorities().containsAll(Set.of(
				new SimpleGrantedAuthority("SCOPE_openid")))).isTrue();

		assertThat(((OidcUser) auth.getPrincipal()).getEmail()).isEqualTo("test@c4-soft.com");
	}

	@Test
	public void customFrequent() {
		final SimpleGrantedAuthority scopeAAuthority = new SimpleGrantedAuthority("SCOPE_b");
		final SimpleGrantedAuthority scopeBAuthority = new SimpleGrantedAuthority("SCOPE_a");
		final SimpleGrantedAuthority scopeOpenId = new SimpleGrantedAuthority("SCOPE_openid");
		final OAuth2LoginAuthenticationToken auth = (OAuth2LoginAuthenticationToken) factory
				.createSecurityContext(AnnotationUtils.findAnnotation(CustomFrequent.class, WithMockOidcIdToken.class))
				.getAuthentication();

		assertThat(auth.getAccessToken().getScopes()).hasSize(3);
		assertThat(auth.getAccessToken().getScopes()).contains("a", "b", "openid");

		final OAuth2AuthorizationRequest authorizationRequest =
				auth.getAuthorizationExchange().getAuthorizationRequest();
		assertThat(authorizationRequest.getScopes()).hasSize(3);
		assertThat(authorizationRequest.getScopes()).contains("a", "b", "openid");

		assertThat(auth.getAuthorities())
				.containsExactlyInAnyOrder(scopeAAuthority, scopeBAuthority, scopeOpenId);

		assertThat(auth.getName()).isEqualTo("Some One");

		assertThat(auth.getClientRegistration().getScopes()).hasSize(3);
		assertThat(auth.getClientRegistration().getScopes()).contains("a", "b", "openid");

		final DefaultOidcUser principal = (DefaultOidcUser) auth.getPrincipal();
		assertThat(principal.getSubject()).isEqualTo("SomeId");
		assertThat(principal.getName()).isEqualTo("Some One");
		assertThat(auth.getPrincipal().getAuthorities()).hasSize(3);
		assertThat(auth.getPrincipal().getAuthorities().contains(scopeAAuthority)).isTrue();
		assertThat(auth.getPrincipal().getAuthorities().contains(scopeBAuthority)).isTrue();
		assertThat(auth.getPrincipal().getAuthorities().contains(scopeOpenId)).isTrue();
	}

	@Test
	public void customFull() throws Exception {
		final OAuth2LoginAuthenticationToken auth = (OAuth2LoginAuthenticationToken) factory
				.createSecurityContext(AnnotationUtils.findAnnotation(CustomFull.class, WithMockOidcIdToken.class))
				.getAuthentication();

		final OAuth2AccessToken accessToken = auth.getAccessToken();
		assertThat(accessToken.getExpiresAt()).isNotNull();
		assertThat(accessToken.getIssuedAt()).isNotNull();
		assertThat(accessToken.getScopes()).containsExactlyInAnyOrder("a", "b", "openid", "email");
		assertThat(accessToken.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(accessToken.getTokenValue()).isEqualTo(Defaults.BEARER_TOKEN_VALUE);

		assertThat(auth.getAuthorities()).hasSize(4);
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_a"))).isTrue();
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_b"))).isTrue();
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_openid"))).isTrue();
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_email"))).isTrue();

		final OAuth2AuthorizationRequest authorizationRequest =
				auth.getAuthorizationExchange().getAuthorizationRequest();
		assertThat(authorizationRequest.getAttributes()).hasSize(6);
		assertThat(authorizationRequest.getAttributes().get(IdTokenClaimNames.SUB)).isEqualTo("SomeId");
		assertThat((Instant) authorizationRequest.getAttributes().get(IdTokenClaimNames.IAT)).isNotNull();
		assertThat((Instant) authorizationRequest.getAttributes().get(IdTokenClaimNames.EXP)).isNotNull();
		assertThat(authorizationRequest.getAttributes().get(OAuth2IntrospectionClaimNames.SCOPE)).isNotNull();
		assertThat(authorizationRequest.getAttributes().get(OAuth2IntrospectionClaimNames.USERNAME)).isEqualTo("truc");
		assertThat(authorizationRequest.getAttributes().get(OAuth2IntrospectionClaimNames.TOKEN_TYPE)).isEqualTo("bearer");
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo("https://localhost:8080/authorize");
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo("https://localhost:8080/authorize");
		assertThat(authorizationRequest.getClientId()).isEqualTo("test-client");
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.IMPLICIT);
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo("https://localhost:8080/");
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.TOKEN);
		assertThat(authorizationRequest.getScopes()).hasSize(4);
		assertThat(authorizationRequest.getScopes()).contains("a", "b", "openid", "email");

		final OAuth2AuthorizationResponse authorizationResponse =
				auth.getAuthorizationExchange().getAuthorizationResponse();
		assertThat(authorizationResponse.getCode()).isEqualTo("test-authorization-success-code");
		assertThat(authorizationResponse.getError()).isNull();
		assertThat(authorizationResponse.getRedirectUri()).isEqualTo("https://localhost:8080/");

		final ClientRegistration clientRegistration = auth.getClientRegistration();
		assertThat(clientRegistration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.IMPLICIT);
		assertThat(clientRegistration.getClientAuthenticationMethod().getValue()).isEqualTo("basic");
		assertThat(clientRegistration.getClientId()).isEqualTo("test-client");
		assertThat(clientRegistration.getClientName()).isEqualTo("implicit-test-client-registration");
		assertThat(clientRegistration.getClientSecret()).isEqualTo("");
		assertThat(clientRegistration.getProviderDetails()).isNotNull();
		assertThat(clientRegistration.getRedirectUriTemplate()).isEqualTo("https://localhost:8080/");
		assertThat(clientRegistration.getRegistrationId()).isEqualTo("implicit-test-client-registration");
		assertThat(clientRegistration.getScopes()).containsExactlyInAnyOrder("a", "b", "openid", "email");

		assertThat(auth.getCredentials()).isEqualTo("");

		assertThat(auth.getDetails()).isNull();

		assertThat(auth.getName()).isEqualTo("truc");

		assertThat(auth.getPrincipal()).isInstanceOf(DefaultOidcUser.class);
		final DefaultOidcUser principal = (DefaultOidcUser) auth.getPrincipal();
		assertThat(principal.getSubject()).isEqualTo("SomeId");
		assertThat(principal.getName()).isEqualTo("truc");
		assertThat(principal.getClaims()).hasSize(11);
		assertThat(principal.getClaimAsStringList(IdTokenClaimNames.AUD)).containsExactlyInAnyOrder("test-client", "other-client");
		assertThat(principal.getClaimAsInstant(IdTokenClaimNames.AUTH_TIME)).isNotNull();
		assertThat(principal.getClaimAsString(IdTokenClaimNames.IAT)).isNotNull();
		assertThat(principal.getClaimAsString(IdTokenClaimNames.EXP)).isNotNull();
		assertThat(principal.getClaimAsString(IdTokenClaimNames.ISS)).isEqualTo("https://test-issuer.org");
		assertThat(principal.getClaimAsString(IdTokenClaimNames.SUB)).isEqualTo("SomeId");
		assertThat(principal.getClaimAsString(StandardClaimNames.EMAIL)).isEqualTo("truc@c4-soft.com");
		assertThat(principal.getClaimAsString(StandardClaimNames.EMAIL_VERIFIED)).isEqualTo("true");
		assertThat(principal.getClaimAsString("nameTestKey")).isEqualTo("truc");
		assertThat(principal.getClaimAsString("private-id-token-claim")).isEqualTo("test-value");
		assertThat(principal.getClaimAsString("private-user-info-claim")).isEqualTo("test-value");
		assertThat(principal.getAuthorities()).hasSize(4);
		assertThat(principal.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_a"))).isTrue();
		assertThat(principal.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_b"))).isTrue();
		assertThat(principal.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_openid"))).isTrue();
		assertThat(principal.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_email"))).isTrue();

		assertThat(auth.getRefreshToken()).isNull();
	}

}
