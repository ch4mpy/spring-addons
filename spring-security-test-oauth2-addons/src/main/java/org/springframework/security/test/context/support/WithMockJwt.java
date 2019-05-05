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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Collection;

import org.springframework.core.annotation.AliasFor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
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
import org.springframework.security.test.context.support.WithMockJwt.Factory;
import org.springframework.security.test.support.jwt.JwtAuthenticationTokenTestingBuilder;
import org.springframework.test.context.TestContext;
import org.springframework.test.web.servlet.MockMvc;

/**
 * <p>
 * A lot like {@link WithMockUser @WithMockUser}: when used with {@link WithSecurityContextTestExecutionListener} this
 * annotation can be added to a test method to emulate running with a mocked authentication created out of a {@link Jwt
 * JWT}.
 * </p>
 * <p>
 * Main steps are:
 * </p>
 * <ul>
 * <li>A {@link Jwt JWT} is created as per this annotation {@code name} (forces {@code subject} claim), {@code headers}
 * and {@code claims}</li>
 * <li>A {@link JwtAuthenticationToken JwtAuthenticationToken} is then created and fed with this new JWT token</li>
 * <li>An empty {@link SecurityContext} is instantiated and populated with this {@code JwtAuthenticationToken}</li>
 * </ul>
 * <p>
 * As a result, the {@link Authentication} {@link MockMvc} gets from security context will have the following
 * properties:
 * </p>
 * <ul>
 * <li>{@link Authentication#getPrincipal() getPrincipal()} returns a {@link Jwt}</li>
 * <li>{@link Authentication#getName() getName()} returns the JWT {@code subject} claim, set from this annotation
 * {@code name} value ({@code "user"} by default)</li>
 * <li>{@link Authentication#getAuthorities() authorities} will be a collection of {@link SimpleGrantedAuthority} as
 * defined by this annotation {@link #authorities()} ({@code "ROLE_USER" } by default)</li>
 * </ul>
 *
 * Sample Usage:
 *
 * <pre>
 * &#64;WithMockJwt
 * &#64;Test
 * public void testSomethingWithDefaultJwtAuthentication() {
 *   //identified as "user" granted with [ROLE_USER]
 *   //claims contain "sub" (subject) with "ch4mpy" as value
 *   //headers can't be empty, so a default one is set
 *   ...
 * }
 *
 * &#64;WithMockJwt({"ROLE_USER", "ROLE_ADMIN"})
 * &#64;Test
 * public void testSomethingWithCustomJwtAuthentication() {
 *   //identified as "user" granted with [ROLE_USER, ROLE_ADMIN]
 *   ...
 * }
 *
 * &#64;WithMockJwt(claims = &#64;StringAttribute(name = "scp", value = "message:read message:write"), scopesClaimeName = "scp")
 * &#64;Test
 * public void testSomethingWithCustomJwtAuthentication() {
 *   //identified as "user" granted with [SCOPE_message:read, SCOPE_message:write]
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
public @interface WithMockJwt {

	@AliasFor("claims")
	StringAttribute[] value() default {};

	/**
	 * @return JWT claims
	 */
	@AliasFor("value")
	StringAttribute[] claims() default {};

	/**
	 * Of little use at unit test time...
	 * @return JWT headers
	 */
	StringAttribute[] headers() default {};

	String tokenValue() default Defaults.JWT_VALUE;

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 * @return the {@link TestExecutionEvent} to initialize before
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public final class Factory implements WithSecurityContextFactory<WithMockJwt> {
		private final StringAttributeParserSupport parsingSupport = new StringAttributeParserSupport();

		private final Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

		public Factory(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			this.authoritiesConverter = authoritiesConverter;
		}

		@Override
		public SecurityContext createSecurityContext(WithMockJwt annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(authentication(annotation));

			return context;
		}

		public JwtAuthenticationToken authentication(WithMockJwt annotation) {
			final var authenticationBuilder = new JwtAuthenticationTokenTestingBuilder(authoritiesConverter);
			return authenticationBuilder
					.token(jwt -> jwt
							.tokenValue(annotation.tokenValue())
							.headers(this.parsingSupport.parse(annotation.headers()))
							.claims(this.parsingSupport.parse(annotation.claims())))
					.build();
		}
	}
}
