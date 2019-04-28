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
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.SCOPE;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.USERNAME;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
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
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.test.context.support.StringAttribute.InstantParser;
import org.springframework.security.test.context.support.StringAttribute.StringListParser;
import org.springframework.security.test.context.support.StringAttribute.UrlParser;
import org.springframework.security.test.context.support.WithMockOidcIdToken.Factory;
import org.springframework.security.test.support.Defaults;
import org.springframework.security.test.support.OAuth2LoginAuthenticationTokenBuilder;
import org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames;

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

	@WithMockOidcIdToken(@StringAttribute(name = SCOPE, value = "a b"))
	private static class CustomMini {
	}

	@WithMockOidcIdToken(
			claims = {
					@StringAttribute(name = IdTokenClaimNames.SUB, value = "Some One"),
					@StringAttribute(name = SCOPE, value = "a b")},
			openIdClaims = {
					@StringAttribute(name = IdTokenClaimNames.SUB, value = "Some One") })
	private static class CustomFrequent {
	}

	@WithMockOidcIdToken(
			nameAttributeKey = USERNAME,
			claims = {
					@StringAttribute(name = USERNAME, value = "truc"),
					@StringAttribute(name = SCOPE, value = "a b"),
					@StringAttribute(name = IdTokenClaimNames.AUD, value = "test-audience", parser = StringListParser.class),
					@StringAttribute(name = IdTokenClaimNames.AUD, value = "other-audience", parser = StringListParser.class),
					@StringAttribute(name = IdTokenClaimNames.ISS, value = "https://test-issuer.org", parser = UrlParser.class),
					@StringAttribute(name = IdTokenClaimNames.IAT, value = "2019-03-03T22:35:00.0Z", parser = InstantParser.class) },
			openIdClaims = { @StringAttribute(name = USERNAME, value = "truc") },
			authorizationRequest = @MockOAuth2AuthorizationRequest(
					authorizationGrantType = "implicit",
					authorizationUri = "https://localhost:8080/authorize",
					clientId = "mocked-client",
					redirectUri = "https://localhost:8080/"),
			clientRegistration = @MockClientRegistration(
					authorizationGrantType = "implicit",
					registrationId = "authorization_code-mocked-client-registration",
					clientId = "mocked-client",
					tokenUri = "https://localhost:8080/token",
					redirectUriTemplate = "https://localhost:8080/",
					authorizationUri = "https://localhost:8080/authorize"))
	private static class CustomFull {
	}

	@Test
	public void defaults() {
		final OAuth2LoginAuthenticationToken auth = (OAuth2LoginAuthenticationToken) factory
				.createSecurityContext(AnnotationUtils.findAnnotation(Default.class, WithMockOidcIdToken.class))
				.getAuthentication();

		final OAuth2AccessToken accessToken = auth.getAccessToken();
		assertThat(accessToken.getExpiresAt()).isNull();
		assertThat(accessToken.getIssuedAt()).isNull();
		assertThat(accessToken.getScopes()).containsExactlyInAnyOrder("ROLE_USER");
		assertThat(accessToken.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(accessToken.getTokenValue()).isEqualTo(OAuth2LoginAuthenticationTokenBuilder.DEFAULT_TOKEN_VALUE);

		assertThat(auth.getAuthorities()).containsExactly(new SimpleGrantedAuthority("SCOPE_ROLE_USER"));

		final OAuth2AuthorizationRequest authorizationRequest =
				auth.getAuthorizationExchange().getAuthorizationRequest();
		assertThat(authorizationRequest.getAttributes()).hasSize(2);
		assertThat(authorizationRequest.getAttributes().get(IdTokenClaimNames.SUB)).isEqualTo("user");
		assertThat(authorizationRequest.getAttributes().get(OAuth2IntrospectionClaimNames.SCOPE)).isEqualTo("ROLE_USER");
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo(
				"https://localhost:8080/authorize?response_type=code&client_id=mocked-client&scope=ROLE_USER&redirect_uri=https://localhost:8080/&sub=user");
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo("https://localhost:8080/authorize");
		assertThat(authorizationRequest.getClientId()).isEqualTo("mocked-client");
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo("https://localhost:8080/");
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.CODE);
		assertThat(authorizationRequest.getScopes()).containsExactlyInAnyOrder("ROLE_USER");

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
		assertThat(clientRegistration.getRedirectUriTemplate()).isNull();
		assertThat(clientRegistration.getRegistrationId()).isEqualTo("mocked-registration");
		assertThat(clientRegistration.getScopes()).containsExactlyInAnyOrder("ROLE_USER");

		assertThat(auth.getCredentials()).isEqualTo("");

		assertThat(auth.getDetails()).isNull();

		assertThat(auth.getName()).isEqualTo(Defaults.AUTH_NAME);

		assertThat(auth.getPrincipal()).isInstanceOf(DefaultOidcUser.class);
		final DefaultOidcUser principal = (DefaultOidcUser) auth.getPrincipal();
		assertThat(principal.getSubject()).isEqualTo(Defaults.AUTH_NAME);
		assertThat(principal.getClaims()).hasSize(1);
		assertThat(principal.getAuthorities()).hasSize(1);
		assertThat(principal.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_ROLE_USER"))).isTrue();

		assertThat(auth.getRefreshToken()).isNull();
	}

	@Test
	public void customMini() {
		final OAuth2LoginAuthenticationToken auth = (OAuth2LoginAuthenticationToken) factory
				.createSecurityContext(AnnotationUtils.findAnnotation(CustomMini.class, WithMockOidcIdToken.class))
				.getAuthentication();

		assertThat(auth.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("SCOPE_a"),
				new SimpleGrantedAuthority("SCOPE_b"));

		assertThat(auth.getPrincipal().getAuthorities()).hasSize(2);
		assertThat(auth.getPrincipal().getAuthorities().containsAll(Set.of(
				new SimpleGrantedAuthority("SCOPE_a"),
				new SimpleGrantedAuthority("SCOPE_b")))).isTrue();
	}

	@Test
	public void customFrequent() {
		final SimpleGrantedAuthority scopeAAuthority = new SimpleGrantedAuthority("SCOPE_b");
		final SimpleGrantedAuthority scopeBAuthority = new SimpleGrantedAuthority("SCOPE_a");
		final OAuth2LoginAuthenticationToken auth = (OAuth2LoginAuthenticationToken) factory
				.createSecurityContext(AnnotationUtils.findAnnotation(CustomFrequent.class, WithMockOidcIdToken.class))
				.getAuthentication();

		assertThat(auth.getAccessToken().getScopes()).hasSize(2);
		assertThat(auth.getAccessToken().getScopes()).contains("a", "b");

		final OAuth2AuthorizationRequest authorizationRequest =
				auth.getAuthorizationExchange().getAuthorizationRequest();
		assertThat(authorizationRequest.getScopes()).hasSize(2);
		assertThat(authorizationRequest.getScopes()).contains("a", "b");

		assertThat(auth.getAuthorities())
				.containsExactlyInAnyOrder(scopeAAuthority, scopeBAuthority);

		assertThat(auth.getName()).isEqualTo("Some One");

		assertThat(auth.getClientRegistration().getScopes()).hasSize(2);
		assertThat(auth.getClientRegistration().getScopes()).contains("a", "b");

		final DefaultOidcUser principal = (DefaultOidcUser) auth.getPrincipal();
		assertThat(principal.getSubject()).isEqualTo("Some One");
		assertThat(principal.getName()).isEqualTo("Some One");
		assertThat(auth.getPrincipal().getAuthorities()).hasSize(2);
		assertThat(auth.getPrincipal().getAuthorities().contains(scopeAAuthority)).isTrue();
		assertThat(auth.getPrincipal().getAuthorities().contains(scopeBAuthority)).isTrue();
	}

	@Test
	@SuppressWarnings("unchecked")
	public void customFull() throws Exception {
		final OAuth2LoginAuthenticationToken auth = (OAuth2LoginAuthenticationToken) factory
				.createSecurityContext(AnnotationUtils.findAnnotation(CustomFull.class, WithMockOidcIdToken.class))
				.getAuthentication();

		final OAuth2AccessToken accessToken = auth.getAccessToken();
		assertThat(accessToken.getExpiresAt()).isNull();
		assertThat(accessToken.getIssuedAt()).isEqualTo(Instant.parse("2019-03-03T22:35:00.0Z"));
		assertThat(accessToken.getScopes()).hasSize(2);
		assertThat(accessToken.getScopes()).contains("a", "b");
		assertThat(accessToken.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(accessToken.getTokenValue()).isEqualTo(OAuth2LoginAuthenticationTokenBuilder.DEFAULT_TOKEN_VALUE);

		assertThat(auth.getAuthorities()).hasSize(2);
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_a"))).isTrue();
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_b"))).isTrue();

		final OAuth2AuthorizationRequest authorizationRequest =
				auth.getAuthorizationExchange().getAuthorizationRequest();
		assertThat(authorizationRequest.getAttributes()).hasSize(5);
		assertThat((Collection<String>) authorizationRequest.getAttributes().get(IdTokenClaimNames.AUD))
				.containsExactly("test-audience", "other-audience");
		assertThat((Instant) authorizationRequest.getAttributes().get(IdTokenClaimNames.IAT))
				.isEqualTo(Instant.parse("2019-03-03T22:35:00Z"));
		assertThat((URL) authorizationRequest.getAttributes().get(IdTokenClaimNames.ISS))
				.isEqualTo(new URL("https://test-issuer.org"));
		assertThat(authorizationRequest.getAttributes().get("scope")).isEqualTo("a b");
		assertThat(authorizationRequest.getAttributes().get("username")).isEqualTo("truc");
		assertThat(authorizationRequest.getAuthorizationRequestUri()).isEqualTo(
				"https://localhost:8080/authorize?response_type=token&client_id=mocked-client&scope=a%20b&redirect_uri=https://localhost:8080/&iss=https://test-issuer.org&aud=%5Btest-audience,%20other-audience%5D&iat=2019-03-03T22:35:00Z&username=truc");
		assertThat(authorizationRequest.getAuthorizationUri()).isEqualTo("https://localhost:8080/authorize");
		assertThat(authorizationRequest.getClientId()).isEqualTo("mocked-client");
		assertThat(authorizationRequest.getGrantType()).isEqualTo(AuthorizationGrantType.IMPLICIT);
		assertThat(authorizationRequest.getRedirectUri()).isEqualTo("https://localhost:8080/");
		assertThat(authorizationRequest.getResponseType()).isEqualTo(OAuth2AuthorizationResponseType.TOKEN);
		assertThat(authorizationRequest.getScopes()).hasSize(2);
		assertThat(authorizationRequest.getScopes()).contains("a", "b");

		final OAuth2AuthorizationResponse authorizationResponse =
				auth.getAuthorizationExchange().getAuthorizationResponse();
		assertThat(authorizationResponse.getCode()).isEqualTo("test-authorization-success-code");
		assertThat(authorizationResponse.getError()).isNull();
		assertThat(authorizationResponse.getRedirectUri()).isEqualTo("https://localhost:8080/");

		final ClientRegistration clientRegistration = auth.getClientRegistration();
		assertThat(clientRegistration.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.IMPLICIT);
		assertThat(clientRegistration.getClientAuthenticationMethod().getValue()).isEqualTo("basic");
		assertThat(clientRegistration.getClientId()).isEqualTo("mocked-client");
		assertThat(clientRegistration.getClientName()).isEqualTo("authorization_code-mocked-client-registration");
		assertThat(clientRegistration.getClientSecret()).isEqualTo("");
		assertThat(clientRegistration.getProviderDetails()).isNotNull();
		assertThat(clientRegistration.getRedirectUriTemplate()).isEqualTo("https://localhost:8080/");
		assertThat(clientRegistration.getRegistrationId()).isEqualTo("authorization_code-mocked-client-registration");
		assertThat(clientRegistration.getScopes()).hasSize(2);
		assertThat(clientRegistration.getScopes()).contains("a", "b");

		assertThat(auth.getCredentials()).isEqualTo("");

		assertThat(auth.getDetails()).isNull();

		assertThat(auth.getName()).isEqualTo("truc");

		assertThat(auth.getPrincipal()).isInstanceOf(DefaultOidcUser.class);
		final DefaultOidcUser principal = (DefaultOidcUser) auth.getPrincipal();
		assertThat(principal.getSubject()).isNull();
		assertThat(principal.getName()).isEqualTo("truc");
		assertThat(principal.getClaims()).hasSize(1);
		assertThat(principal.getClaimAsString("username")).isEqualTo("truc");
		assertThat(principal.getAuthorities()).hasSize(2);
		assertThat(principal.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_a"))).isTrue();
		assertThat(principal.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_b"))).isTrue();

		assertThat(auth.getRefreshToken()).isNull();
	}

}
