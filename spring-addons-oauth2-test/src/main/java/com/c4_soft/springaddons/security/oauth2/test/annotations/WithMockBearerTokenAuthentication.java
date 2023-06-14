/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link BearerTokenAuthentication}. Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockOidcId(
			authorities = { "USER", "AUTHORIZED_PERSONNEL" },
			claims = &#64;OpenIdClaims(
					sub = "42",
					email = "ch4mp@c4-soft.com",
					emailVerified = true,
					nickName = "Tonton-Pirate",
					preferredUsername = "ch4mpy",
					otherClaims = &#64;ClaimSet(stringClaims = &#64;StringClaim(name = "foo", value = "bar"))))
 * public void test() {
 *     ...
 * }
 * </pre>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockBearerTokenAuthentication.AuthenticationFactory.class)
public @interface WithMockBearerTokenAuthentication {

	@AliasFor("authorities")
	String[] value() default {};

	@AliasFor("value")
	String[] authorities() default {};

	OpenIdClaims attributes() default @OpenIdClaims();

	String bearerString() default "machin.truc.chose";

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public static final class AuthenticationFactory
			extends AbstractAnnotatedAuthenticationBuilder<WithMockBearerTokenAuthentication, BearerTokenAuthentication> {
		@Override
		public BearerTokenAuthentication authentication(WithMockBearerTokenAuthentication annotation) {
			final var claims = super.claims(annotation.attributes()).build();
			final var authorities = super.authorities(annotation.authorities(), annotation.value());
			final var principal = new OAuth2IntrospectionAuthenticatedPrincipal(claims.getName(), claims, authorities);
			final var credentials = new OAuth2AccessToken(
					OAuth2AccessToken.TokenType.BEARER,
					annotation.bearerString(),
					claims.getAsInstant(JwtClaimNames.IAT),
					claims.getAsInstant(JwtClaimNames.EXP));
			return new BearerTokenAuthentication(principal, credentials, authorities);
		}
	}
}
