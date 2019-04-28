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

import static org.springframework.util.StringUtils.isEmpty;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

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
import org.springframework.security.test.support.OAuth2LoginAuthenticationTokenBuilder;
import org.springframework.security.test.support.OAuth2LoginAuthenticationTokenBuilder.AuthorizationRequestBuilder;
import org.springframework.security.test.support.OAuth2LoginAuthenticationTokenBuilder.ClientRegistrationBuilder;
import org.springframework.test.context.TestContext;
import org.springframework.test.web.servlet.MockMvc;

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
 * @deprecated this is a draft not ready for use: I don't know enough about OpenID spec and have not understood enough of Spring impl to provide anything reliable yet
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = Factory.class)
@Deprecated
public @interface WithMockOidcIdToken {

	String tokenValue() default OAuth2LoginAuthenticationTokenBuilder.DEFAULT_TOKEN_VALUE;

	/**
	 * Alias for claims
	 * @return introspection access-token claims
	 */
	@AliasFor("claims")
	StringAttribute[] value() default {};

	/**
	 * @return claim name for subscriber (user name). Default value is very likely to match your need.
	 */
	String nameAttributeKey() default OAuth2LoginAuthenticationTokenBuilder.DEFAULT_NAME_ATTRIBUTE_KEY;

	/**
	 * @return introspection access-token claims
	 */
	@AliasFor("value")
	StringAttribute[] claims() default {};

	/**
	 * @return OpenID token claims
	 */
	StringAttribute[] openIdClaims() default {};

	/**
	 * Are you sure you need to configure that ? We are building an already granted
	 * {@link OAuth2LoginAuthenticationToken}. So, unless the controller method under test (or annotation SpEL)
	 * explicitly accesses client registration, you are safe to keep defaults.
	 * @return {@link ClientRegistration} details
	 */
	MockClientRegistration clientRegistration() default @MockClientRegistration;

	/**
	 * Are you sure you need to configure that ? We are building an already granted
	 * {@link OAuth2LoginAuthenticationToken}. So, unless the controller method under test (or annotation SpEL)
	 * explicitly accesses authorization request, you are safe to keep defaults.
	 * @return {@link OAuth2AuthorizationRequest} details
	 */
	MockOAuth2AuthorizationRequest authorizationRequest() default @MockOAuth2AuthorizationRequest;

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

		private final StringAttributeParserSupport parsingSupport = new StringAttributeParserSupport();

		@Override
		public SecurityContext createSecurityContext(
				WithMockOidcIdToken annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(authentication(annotation));

			return context;
		}

		/**
		 * Specialized {@link OAuth2LoginAuthenticationToken} to work with
		 * {@link WithMockOidcIdToken @WithMockOidcIdToken}
		 *
		 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
		 * @since 5.2
		 */
		public OAuth2LoginAuthenticationToken authentication(
				WithMockOidcIdToken annotation) {
			final var authentication = new OAuth2LoginAuthenticationTokenBuilder(
					new AuthorizationGrantType(annotation.authorizationRequest().authorizationGrantType()))
							.nameAttributeKey(annotation.nameAttributeKey())
							.attributes(parsingSupport.parse(annotation.claims()))
							.openIdClaims(parsingSupport.parse(annotation.openIdClaims()))
							.tokenValue(nonEmptyOrNull(annotation.tokenValue()));

			configure(authentication.getClientRegistrationBuilder(), annotation.clientRegistration());
			configure(authentication.getAuthorizationRequestBuilder(), annotation.authorizationRequest());

			return authentication.build();
		}

		private void configure(
				ClientRegistrationBuilder builder,
				MockClientRegistration annotation) {
			builder.authorizationGrantType(
					isEmpty(annotation.authorizationGrantType()) ? null
							: new AuthorizationGrantType(annotation.authorizationGrantType()));
			builder.authorizationUri(nonEmptyOrNull(annotation.authorizationUri()));
			builder.clientAuthenticationMethod(
					isEmpty(annotation.clientAuthenticationMethod()) ? null
							: new ClientAuthenticationMethod(annotation.clientAuthenticationMethod()));
			builder.clientId(nonEmptyOrNull(annotation.clientId()));
			builder.clientName(nonEmptyOrNull(annotation.clientName()));
			builder.clientSecret(nonEmptyOrNull(annotation.clientSecret()));
			builder.jwkSetUri(nonEmptyOrNull(annotation.jwkSetUri()));
			builder.redirectUriTemplate(nonEmptyOrNull(annotation.redirectUriTemplate()));
			builder.providerConfigurationMetadata(
					parsingSupport.parse(annotation.providerConfigurationMetadata()));
			builder.registrationId(nonEmptyOrNull(annotation.registrationId()));
			builder.tokenUri(nonEmptyOrNull(annotation.tokenUri()));
			builder.userInfoAuthenticationMethod(
					isEmpty(annotation.userInfoAuthenticationMethod()) ? null
							: new AuthenticationMethod(annotation.userInfoAuthenticationMethod()));
			builder.userInfoUri(nonEmptyOrNull(annotation.userInfoUri()));
			builder.userNameAttributeName(nonEmptyOrNull(annotation.userNameAttributeName()));
		}

		private void configure(
				AuthorizationRequestBuilder builder,
				MockOAuth2AuthorizationRequest annotation) {
			builder.authorizationRequestUri(nonEmptyOrNull(annotation.authorizationRequestUri()));
			builder.authorizationUri(nonEmptyOrNull(annotation.authorizationUri()));
			builder.clientId(nonEmptyOrNull(annotation.clientId()));
			builder.redirectUri(nonEmptyOrNull(annotation.redirectUri()));
			parsingSupport.parse(annotation.additionalParameters()).forEach((name, value) -> builder.additionalParameter(name, value));
		}

		private static String nonEmptyOrNull(
				String value) {
			return isEmpty(value) ? null : value;
		}

	}
}
