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
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.ACTIVE;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.AUDIENCE;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.ISSUED_AT;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.ISSUER;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.JTI;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.NOT_BEFORE;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.SCOPE;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.SUBJECT;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.TOKEN_TYPE;
import static org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames.USERNAME;

import java.time.Instant;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.test.configuration.Defaults;
import org.springframework.security.test.context.support.StringAttribute.BooleanParser;
import org.springframework.security.test.context.support.StringAttribute.InstantParser;
import org.springframework.security.test.context.support.StringAttribute.StringListParser;
import org.springframework.security.test.context.support.WithMockIntrospectionToken.Factory;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class WithMockIntrospectionTokenSecurityContextFactoryTests {

	private Factory factory;

	@Before
	public void setup() {
		factory = new Factory();
	}

	@WithMockIntrospectionToken
	private static class Default {
	}

	@WithMockIntrospectionToken("a")
	private static class CustomMini {
	}

	@WithMockIntrospectionToken(name = "ch4mpy", scopes = { "message:read", "message:write" })
	private static class SameAsResourceSreverOpaqueSampleIntegrationTests {
	}

	@WithMockIntrospectionToken(
			name = "abracadabra",
			scopes = "a",
			attributes = {
					@StringAttribute(name = ACTIVE, value = "false", parser = BooleanParser.class),
					@StringAttribute(name = AUDIENCE, value = "c", parser = StringListParser.class),
					@StringAttribute(name = AUDIENCE, value = "d", parser = StringListParser.class),
					@StringAttribute(name = CLIENT_ID, value = "test-client"),
					@StringAttribute(name = EXPIRES_AT, value = "2019-02-04T13:59:42.00Z", parser = InstantParser.class),
					@StringAttribute(name = ISSUED_AT, value = "2019-02-03T13:59:42.00Z", parser = InstantParser.class),
					@StringAttribute(name = ISSUER, value = "test-issuer"),
					@StringAttribute(name = JTI, value = "test ID"),
					@StringAttribute(name = NOT_BEFORE, value = "2019-02-03T14:00:42.00Z", parser = InstantParser.class),
					@StringAttribute(name = SCOPE, value = "b"),
					@StringAttribute(name = SUBJECT, value = "test-subject")})
	private static class CustomFull {
	}

	@Test
	public void defaults() {
		final WithMockIntrospectionToken authAnnotation =
				AnnotationUtils.findAnnotation(Default.class, WithMockIntrospectionToken.class);
		final OAuth2IntrospectionAuthenticationToken auth =
				(OAuth2IntrospectionAuthenticationToken) factory.createSecurityContext(authAnnotation)
						.getAuthentication();
		final OAuth2AccessToken token = (OAuth2AccessToken) auth.getCredentials();
		final Map<String, Object> attributes = auth.getTokenAttributes();

		assertThat(auth.getAuthorities()).hasSize(1);
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_USER"))).isTrue();
		assertThat(auth.getCredentials()).isEqualTo(token);
		assertThat(auth.getDetails()).isNull();
		assertThat(auth.getName()).isEqualTo(Defaults.AUTH_NAME);
		assertThat(auth.getPrincipal()).isInstanceOf(Map.class);

		assertThat(token.getExpiresAt()).isNull();
		assertThat(token.getIssuedAt()).isNull();
		assertThat(token.getScopes()).containsExactly("USER");
		assertThat(token.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(token.getTokenValue()).isEqualTo(Defaults.BEARER_TOKEN_VALUE);

		assertThat(attributes).hasSize(4);
		assertThat(attributes.get(TOKEN_TYPE)).isEqualTo(TokenType.BEARER.getValue());
		assertThat(attributes.get(USERNAME)).isEqualTo(Defaults.AUTH_NAME);
		assertThat(attributes.get(SCOPE)).isEqualTo("USER");
		assertThat(attributes.get(SUBJECT)).isEqualTo("testuserid");
	}

	@Test
	public void customMini() {
		final WithMockIntrospectionToken authAnnotation =
				AnnotationUtils.findAnnotation(CustomMini.class, WithMockIntrospectionToken.class);
		final OAuth2IntrospectionAuthenticationToken auth =
				(OAuth2IntrospectionAuthenticationToken) factory.createSecurityContext(authAnnotation)
						.getAuthentication();
		final OAuth2AccessToken token = (OAuth2AccessToken) auth.getCredentials();
		final Map<String, Object> attributes = auth.getTokenAttributes();

		assertThat(auth.getAuthorities()).hasSize(1);
		assertThat(auth.getAuthorities()).contains(new SimpleGrantedAuthority("SCOPE_a"));
		assertThat(auth.getCredentials()).isEqualTo(token);
		assertThat(auth.getDetails()).isNull();
		assertThat(auth.getName()).isEqualTo(Defaults.AUTH_NAME);
		assertThat(auth.getPrincipal()).isInstanceOf(Map.class);

		assertThat(token.getExpiresAt()).isNull();
		assertThat(token.getIssuedAt()).isNull();
		assertThat(token.getScopes()).containsExactly("a");
		assertThat(token.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(token.getTokenValue()).isEqualTo(Defaults.BEARER_TOKEN_VALUE);

		assertThat(attributes).hasSize(4);
		assertThat(attributes.get(TOKEN_TYPE)).isEqualTo(TokenType.BEARER.getValue());
		assertThat(attributes.get(USERNAME)).isEqualTo(Defaults.AUTH_NAME);
		assertThat(attributes.get(SCOPE)).isEqualTo("a");
		assertThat(attributes.get(SUBJECT)).isEqualTo("testuserid");
	}

	@Test
	public void scopesMixedInAuthoritiesAndClaims() {
		final WithMockIntrospectionToken authAnnotation = AnnotationUtils
				.findAnnotation(SameAsResourceSreverOpaqueSampleIntegrationTests.class, WithMockIntrospectionToken.class);
		final OAuth2IntrospectionAuthenticationToken auth =
				(OAuth2IntrospectionAuthenticationToken) factory.createSecurityContext(authAnnotation)
						.getAuthentication();
		final OAuth2AccessToken token = (OAuth2AccessToken) auth.getCredentials();
		final Map<String, Object> attributes = auth.getTokenAttributes();

		assertThat(auth.getAuthorities()).hasSize(2);
		assertThat(auth.getAuthorities()).contains(new SimpleGrantedAuthority("SCOPE_message:read"));
		assertThat(auth.getAuthorities()).contains(new SimpleGrantedAuthority("SCOPE_message:write"));
		assertThat(auth.getCredentials()).isEqualTo(token);
		assertThat(auth.getDetails()).isNull();
		assertThat(auth.getName()).isEqualTo("ch4mpy");
		assertThat(auth.getPrincipal()).isInstanceOf(Map.class);

		assertThat(token.getExpiresAt()).isNull();
		assertThat(token.getIssuedAt()).isNull();
		assertThat(token.getScopes()).hasSize(2);
		assertThat(token.getScopes()).containsExactlyInAnyOrder("message:read", "message:write");
		assertThat(token.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(token.getTokenValue()).isEqualTo(Defaults.BEARER_TOKEN_VALUE);

		assertThat(attributes).hasSize(4);
		assertThat(attributes.get(TOKEN_TYPE)).isEqualTo(TokenType.BEARER.getValue());
		assertThat(attributes.get(USERNAME)).isEqualTo("ch4mpy");
		assertThat(attributes.get(SCOPE)).isEqualTo("message:read message:write");
		assertThat(attributes.get(SUBJECT)).isEqualTo("testuserid");
	}

	@Test
	public void customFull() throws Exception {
		final WithMockIntrospectionToken authAnnotation =
				AnnotationUtils.findAnnotation(CustomFull.class, WithMockIntrospectionToken.class);
		final OAuth2IntrospectionAuthenticationToken auth =
				(OAuth2IntrospectionAuthenticationToken) factory.createSecurityContext(authAnnotation)
						.getAuthentication();
		final OAuth2AccessToken token = (OAuth2AccessToken) auth.getCredentials();
		final Map<String, Object> attributes = auth.getTokenAttributes();

		assertThat(auth.getAuthorities()).hasSize(2);
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_a")));
		assertThat(auth.getAuthorities().contains(new SimpleGrantedAuthority("SCOPE_b")));

		assertThat(auth.getCredentials()).isEqualTo(token);

		assertThat(auth.getDetails()).isNull();

		assertThat(auth.getName()).isEqualTo("abracadabra");

		assertThat(auth.getPrincipal()).isEqualTo(attributes);

		assertThat(token.getExpiresAt()).isEqualTo(Instant.parse("2019-02-04T13:59:42.00Z"));
		assertThat(token.getIssuedAt()).isEqualTo(Instant.parse("2019-02-03T13:59:42.00Z"));
		assertThat(token.getScopes()).hasSize(2);
		assertThat(token.getScopes()).contains("a", "b");
		assertThat(token.getTokenType()).isEqualTo(TokenType.BEARER);
		assertThat(token.getTokenValue()).isEqualTo(Defaults.BEARER_TOKEN_VALUE);

		assertThat(attributes.get(TOKEN_TYPE)).isEqualTo(TokenType.BEARER.getValue());
		assertThat(attributes.get(USERNAME)).isEqualTo("abracadabra");
	}

}
