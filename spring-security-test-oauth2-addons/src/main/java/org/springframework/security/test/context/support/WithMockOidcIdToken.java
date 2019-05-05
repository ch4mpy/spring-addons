/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.test.context.support;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;
import java.util.stream.Stream;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.test.configuration.Defaults;
import org.springframework.security.test.context.support.StringAttribute.BooleanParser;
import org.springframework.security.test.context.support.StringAttribute.DoubleParser;
import org.springframework.security.test.context.support.StringAttribute.FloatParser;
import org.springframework.security.test.context.support.StringAttribute.InstantParser;
import org.springframework.security.test.context.support.StringAttribute.IntegerParser;
import org.springframework.security.test.context.support.StringAttribute.LongParser;
import org.springframework.security.test.context.support.StringAttribute.NoOpParser;
import org.springframework.security.test.context.support.StringAttribute.SpacedSeparatedStringsParser;
import org.springframework.security.test.context.support.StringAttribute.StringListParser;
import org.springframework.security.test.context.support.StringAttribute.StringSetParser;
import org.springframework.security.test.context.support.StringAttribute.UrlParser;
import org.springframework.security.test.context.support.WithMockOidcIdToken.Factory;
import org.springframework.security.test.support.openid.OAuth2LoginAuthenticationTokenTestingBuilder;
import org.springframework.test.context.TestContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.StringUtils;

/**
 * <p>
 * A lot like {@link WithMockUser @WithMockUser} and {@link WithMockJwt @WithMockJwt}: when used with
 * {@link WithSecurityContextTestExecutionListener} this annotation can be added to a test method to emulate running
 * with a mocked OpenID authentication.
 * </p>
 * <p>
 * Main steps are:
 * </p>
 * <ul>
 * <li>{@link ClientRegistration}, {@link OAuth2AuthorizationExchange}, {@link DefaultOidcUser},
 * {@link OAuth2AccessToken} and {@link OidcIdToken} are created as per this annotation details</li>
 * <li>an {@link OAuth2LoginAuthenticationToken} is then created and fed with above objects</li>
 * <li>an empty {@link SecurityContext} is instantiated and populated with this
 * {@code OAuth2LoginAuthenticationToken}</li>
 * </ul>
 * <p>
 * As a result, the {@link Authentication} {@link MockMvc} gets from security context will has following properties:
 * </p>
 * <ul>
 * <li>{@link Authentication#getPrincipal() getPrincipal()} returns an {@link DefaultOidcUser}</li>
 * <li>{@link Authentication#getName() getName()} returns what was as defined by this annotation {@link #name()} in
 * {@link #nameAttributeKey()} claim ({@code subject} by default)</li>
 * <li>{@link Authentication#getAuthorities() getAuthorities()} will be a collection of {@link SimpleGrantedAuthority}
 * as defined by this annotation {@link #authorities()}, {@link #roles()} and {@link #scopes()}</li>
 * <li>{@link OAuth2AccessToken}, {@link ClientRegistration} and {@link OAuth2AuthorizationRequest} scopes are all the
 * same and as defined by {@link #scopes()} and {@link #authorities() authorities() prefixed with SCOPE_}
 * </ul>
 * Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockOidcIdToken
 * public void testDefaultJwtAuthentication() {
 *   //User name is "user" and authorities are [ROLE_USER]
 * }
 *
 * &#64;Test
 * &#64;WithMockOidcIdToken(name ="ch4mpy", authorities =["ROLE_USER", "SCOPE_message:read"])
 * public void testCustomNameAndAuthorities() {
 *   //User name is "ch4mpy" and authorities are [ROLE_USER, SCOPE_message:read]
 *   //Scope "message:read" is also registered as claim with default key "source"
 * }
 *
 * &#64;Test
 * &#64;WithMockOidcIdToken(scopes = "message:read", scopesClaimeName = "scp")
 * public void testCustomScopeClaim() {
 *   //User name is "user" and authorities are [SCOPE_message:read]
 *   //Scope "message:read" is also registered as claim with default key "scp"
 * }
 *
 * &#64;Test
 * &#64;WithMockOidcIdToken(claims = &#64;StringAttribute(
 *     name = "my-claim",
 *     value = "something",
 *     parser = MyAttributeValueParser.class))
 * public void testCustomScopeClaim() {
 *   //MyAttributeValueParser must implement AttributeValueParser to turn "something" into any Object
 * }
 * </pre>
 *
 * To help testing with custom claims as per last sample, many parsers are provided to parse String values:
 * <ul>
 * <li>{@link BooleanParser}</li>
 * <li>{@link DoubleParser}</li>
 * <li>{@link FloatParser}</li>
 * <li>{@link InstantParser}</li>
 * <li>{@link IntegerParser}</li>
 * <li>{@link LongParser}</li>
 * <li>{@link NoOpParser}</li>
 * <li>{@link SpacedSeparatedStringsParser}</li>
 * <li>{@link StringListParser}</li>
 * <li>{@link StringSetParser}</li>
 * <li>{@link UrlParser}</li>
 * </ul>
 *
 * @see StringAttribute
 * @see AttributeValueParser
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = Factory.class)
public @interface WithMockOidcIdToken {

	String idTokenValue() default Defaults.JWT_VALUE;

	String accessTokenValue() default Defaults.BEARER_TOKEN_VALUE;

	String subject() default Defaults.SUBJECT;

	String nameAttributeKey() default OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_NAME_ATTRIBUTE_KEY;

	String name() default Defaults.AUTH_NAME;

	/**
	 * Alias for claims
	 * @return introspection access-token claims
	 */
	@AliasFor("userInfoClaims")
	StringAttribute[] value() default {};

	/**
	 * @return introspection access-token claims
	 */
	@AliasFor("value")
	StringAttribute[] userInfoClaims() default {};

	StringAttribute[] idTokenClaims() default {};

	String[] nonOpenIdScopes() default {};

	String requestGrantType() default OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_REQUEST_GRANT_TYPE;

	String requestUri() default OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_AUTHORIZATION_URI;

	String authorizationUri() default OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_AUTHORIZATION_URI;

	String clientId() default OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_CLIENT_ID;

	String redirectUri() default OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_REQUEST_REDIRECT_URI;

	String clientRedirectUriTemplate() default OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_REQUEST_REDIRECT_URI;

	String requestState() default OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_REQUEST_STATE;

	String clientGrantType() default OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_CLIENT_GRANT_TYPE;

	String clientAuthenticationMethod() default "";

	String clientName() default "";

	String clientSecret() default "";

	String jwkSetUri() default "";

	StringAttribute[] providerConfigurationMetadata() default {};

	String registrationId() default "";

	String tokenUri() default OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_TOKEN_URI;

	String userInfoAuthenticationMethod() default "";

	String userInfoUri() default "";

	String accessTokenIssuedAt() default Factory.DEFAULT_INSTANT;

	String accessTokenExpiresAt() default Factory.DEFAULT_INSTANT;

	String idTokenIssuedAt() default Factory.DEFAULT_INSTANT;

	String idTokenExpiresAt() default Factory.DEFAULT_INSTANT;

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 * @return the {@link TestExecutionEvent} to initialize before
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	/**
	 * Creates a new SecurityContext containing an {@link OAuth2LoginAuthenticationToken} configured with
	 * {@link WithMockOidcIdToken @WithMockOidcIdToken}
	 *
	 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
	 * @since 5.2
	 */
	public final class Factory implements WithSecurityContextFactory<WithMockOidcIdToken> {
		private static final String DEFAULT_INSTANT = "DEFAULT_INSTANT";

		private final StringAttributeParserSupport parsingSupport = new StringAttributeParserSupport();

		@Override
		public SecurityContext createSecurityContext(WithMockOidcIdToken annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(authentication(annotation));

			return context;
		}

		/**
		 * Specialized {@link OAuth2LoginAuthenticationToken} to work with
		 * {@link WithMockOidcIdToken @WithMockOidcIdToken}
		 *
		 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
		 * @throws URISyntaxException
		 * @since 5.2
		 */
		public OAuth2LoginAuthenticationToken authentication(WithMockOidcIdToken annotation) {
			try {
				final var requestGrantType = new AuthorizationGrantType(annotation.requestGrantType());
				final var auth = new AnnotationOAuth2LoginAuthenticationTokenTestingBuilder(requestGrantType)
						.idTokenValue(annotation.idTokenValue())
						.accessTokenValue(annotation.accessTokenValue())
						.nameAttributeKey(annotation.nameAttributeKey())
						.authorizationUri(new URI(annotation.authorizationUri()))
						.clientId(annotation.clientId())
						.tokenUri(new URI(annotation.tokenUri()))
						.providerConfigurationMetadata(parsingSupport.parse(annotation.providerConfigurationMetadata()));

				auth.ifNotEmpty(auth::subject, annotation.subject())
						.ifNotEmpty(auth::name, annotation.name())
						.ifValidUri(auth::requestUri, annotation.requestUri())
						.ifValidUri(auth::redirectUri, annotation.redirectUri())
						.ifNotEmpty(auth::clientRedirectUriTemplate, annotation.clientRedirectUriTemplate())
						.ifNotEmpty(auth::requestState, annotation.requestState())
						.ifNotEmpty(auth::clientName, annotation.clientName())
						.ifNotEmpty(auth::clientSecret, annotation.clientSecret())
						.ifValidUri(auth::jwkSetUri, annotation.jwkSetUri())
						.ifNotEmpty(auth::registrationId, annotation.registrationId())
						.ifValidUri(auth::userInfoUri, annotation.userInfoUri());

				if (StringUtils.hasLength(annotation.clientGrantType())) {
					auth.clientAuthorizationGrantType(new AuthorizationGrantType(annotation.clientGrantType()));
				}
				if (StringUtils.hasLength(annotation.clientAuthenticationMethod())) {
					auth.clientAuthenticationMethod(new ClientAuthenticationMethod(annotation.clientAuthenticationMethod()));
				}
				if (StringUtils.hasLength(annotation.userInfoAuthenticationMethod())) {
					auth.userInfoAuthenticationMethod(new AuthenticationMethod(annotation.userInfoAuthenticationMethod()));
				}

				parsingSupport.parse(annotation.userInfoClaims()).forEach((name, value) -> auth.userInfoClaim(name, value));
				parsingSupport.parse(annotation.idTokenClaims()).forEach((name, value) -> auth.idTokenClaim(name, value));
				Stream.of(annotation.nonOpenIdScopes()).forEach(auth::scope);

				final Instant now = Instant.now();
				final Instant oneDayFromNow = now.plus(Duration.ofDays(1L));
				final Instant oneWeekFromNow = now.plus(Duration.ofDays(7L));
				if(DEFAULT_INSTANT.equals(annotation.accessTokenIssuedAt())) {
					auth.accessTokenIssuedAt(now);
				} else if(StringUtils.hasLength(annotation.accessTokenIssuedAt())) {
					auth.accessTokenIssuedAt(Instant.parse(annotation.accessTokenIssuedAt()));
				}
				if(DEFAULT_INSTANT.equals(annotation.accessTokenExpiresAt())) {
					auth.accessTokenExpiresAt(oneDayFromNow);
				} else if(StringUtils.hasLength(annotation.accessTokenExpiresAt())) {
					auth.accessTokenExpiresAt(Instant.parse(annotation.accessTokenExpiresAt()));
				}
				if(DEFAULT_INSTANT.equals(annotation.idTokenIssuedAt())) {
					auth.idTokenIssuedAt(now);
				} else if(StringUtils.hasLength(annotation.idTokenIssuedAt())) {
					auth.idTokenIssuedAt(Instant.parse(annotation.idTokenIssuedAt()));
				}
				if(DEFAULT_INSTANT.equals(annotation.idTokenExpiresAt())) {
					auth.idTokenExpiresAt(oneWeekFromNow);
				} else if(StringUtils.hasLength(annotation.idTokenExpiresAt())) {
					auth.idTokenExpiresAt(Instant.parse(annotation.idTokenExpiresAt()));
				}

				return auth.build();
			} catch (final URISyntaxException e) {
				throw new RuntimeException(e);
			}
		}

		private static final class AnnotationOAuth2LoginAuthenticationTokenTestingBuilder
				extends
				OAuth2LoginAuthenticationTokenTestingBuilder<AnnotationOAuth2LoginAuthenticationTokenTestingBuilder> {
			public AnnotationOAuth2LoginAuthenticationTokenTestingBuilder(AuthorizationGrantType requestGrantType) {
				super(requestGrantType);
			}

			public AnnotationOAuth2LoginAuthenticationTokenTestingBuilder
					ifNotEmpty(Function<String, AnnotationOAuth2LoginAuthenticationTokenTestingBuilder> setter, String value) {
				if (StringUtils.hasLength(value)) {
					setter.apply(value);
				}
				return this;
			}

			public AnnotationOAuth2LoginAuthenticationTokenTestingBuilder
					ifValidUri(Function<URI, AnnotationOAuth2LoginAuthenticationTokenTestingBuilder> setter, String value) {
				if (StringUtils.hasLength(value)) {
					try {
						setter.apply(new URI(value));
					} catch (final URISyntaxException e) {
					}
				}
				return this;
			}
		}
	}
}
