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
package com.c4soft.springaddons.security.test.context.support;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.stream.Stream;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.test.context.TestContext;
import org.springframework.test.web.servlet.MockMvc;

import com.c4soft.springaddons.security.test.context.support.StringAttribute.BooleanParser;
import com.c4soft.springaddons.security.test.context.support.StringAttribute.DoubleParser;
import com.c4soft.springaddons.security.test.context.support.StringAttribute.FloatParser;
import com.c4soft.springaddons.security.test.context.support.StringAttribute.InstantParser;
import com.c4soft.springaddons.security.test.context.support.StringAttribute.IntegerParser;
import com.c4soft.springaddons.security.test.context.support.StringAttribute.LongParser;
import com.c4soft.springaddons.security.test.context.support.StringAttribute.NoOpParser;
import com.c4soft.springaddons.security.test.context.support.StringAttribute.SpacedSeparatedStringsParser;
import com.c4soft.springaddons.security.test.context.support.StringAttribute.StringListParser;
import com.c4soft.springaddons.security.test.context.support.StringAttribute.StringSetParser;
import com.c4soft.springaddons.security.test.context.support.StringAttribute.UrlParser;
import com.c4soft.springaddons.security.test.context.support.WithMockIntrospectionToken.Factory;
import com.c4soft.springaddons.security.test.support.Defaults;
import com.c4soft.springaddons.security.test.support.introspection.OAuth2IntrospectionAuthenticationTokenTestingBuilder;

/**
 * <p>
 * A lot like {@link WithMockUser @WithMockUser} and {@link WithMockJwt @WithMockJwt}: when used with
 * {@link WithSecurityContextTestExecutionListener} this annotation can be added to a test method to emulate running
 * with a mocked authentication created out of a Bearer token.
 * </p>
 * <p>
 * Main steps are:
 * </p>
 * <ul>
 * <li>An {@link OAuth2AccessToken} Bearer token is created as per this annotation {@link #name()} (forces
 * {@code username} claim) and {@link #attributes()}</li>
 * <li>A {@link OAuth2IntrospectionAuthenticationToken} is then created and fed with this new token</li>
 * <li>An empty {@link SecurityContext} is instantiated and populated with this
 * {@link OAuth2IntrospectionAuthenticationToken}</li>
 * </ul>
 * <p>
 * As a result, the {@link Authentication} {@link MockMvc} gets from security context will have the following
 * properties:
 * </p>
 * <ul>
 * <li>{@link Authentication#getPrincipal() getPrincipal()} returns an {@link OAuth2AccessToken}</li>
 * <li>{@link Authentication#getName() getName()} returns what was as defined by this annotation {@link #name()}
 * ({@code "user"} by default)</li>
 * <li>{@link Authentication#getAuthorities() getAuthorities()} will be a collection of {@link SimpleGrantedAuthority}
 * as defined by this annotation {@link #authorities()} ({@code "ROLE_USER"} by default)</li>
 * <li>token {@code token_type} claim is always present and forced to {@link TokenType#BEARER Bearer}</li>
 * <li>token {@code username} claim is always present and forced to the value of this annotation {@link #name()}
 * property</li>
 * </ul>
 * Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockAccessToken
 * public void testDefaultAccessTokenAuthentication() {
 *   //authenticated as "user" granted with [ROLE_USER]
 *   ...
 * }
 *
 * &#64;Test
 * &#64;WithMockAccessToken({"SCOPE_message:read", "SCOPE_message:write"})
 * public void testSomethingWithCustomScopes() {
 *   //authenticated as "user" granted with [SCOPE_message:read, SCOPE_message:write}
 *   //scopes are listed as authorities but also contained as token attribute
 *   ...
 * }
 *
 * &#64;Test
 * &#64;WithMockAccessToken(claims = &#64;StringAttribute(name = "scp", value = "message:read message:write"), scopesClaimeName = "scp")
 * public void testSomethingWithCustomScopes() {
 *   //authenticated as "user" granted with [SCOPE_message:read, SCOPE_message:write}
 *   //scopes are listed as authorities but also contained as token attribute
 *   ...
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
 *
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = Factory.class)
public @interface WithMockIntrospectionToken {

	@AliasFor("scopes")
	String[] value() default { "USER" };

	@AliasFor("value")
	String[] scopes() default { "USER" };

	String tokenValue() default Defaults.BEARER_TOKEN_VALUE;

	String name() default Defaults.AUTH_NAME;

	String subject() default Defaults.SUBJECT;

	StringAttribute[] attributes() default {};

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 * @return the {@link TestExecutionEvent} to initialize before
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public final class Factory implements WithSecurityContextFactory<WithMockIntrospectionToken> {

		private final StringAttributeParserSupport parsingSupport = new StringAttributeParserSupport();

		@Override
		public SecurityContext createSecurityContext(
				WithMockIntrospectionToken annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(authentication(annotation));
			return context;
		}

		public OAuth2IntrospectionAuthenticationToken authentication(WithMockIntrospectionToken annotation) {
			final var auth = new OAuth2IntrospectionAuthenticationTokenTestingBuilder<>()
					.token(accessToken -> accessToken
							.value(annotation.tokenValue())
							.attributes(claims -> claims.username(annotation.name()).subject(annotation.subject())));
			parsingSupport.parse(annotation.attributes()).forEach((name, value) -> auth.attribute(name, value));
			Stream.of(annotation.scopes()).forEach(scope -> auth.token(accessToken -> accessToken.attributes(claims -> claims.scope(scope))));
			return auth.build();
		}
	}
}
