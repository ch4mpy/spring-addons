/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link JwtAuthenticationToken}. Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockJwtAuth(
			authorities = { "USER", "AUTHORIZED_PERSONNEL" },
			claims = &#64;OpenIdClaims(sub = "42"))
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
@WithSecurityContext(factory = WithMockJwtAuth.JwtAuthenticationTokenFactory.class)
public @interface WithMockJwtAuth {

	@AliasFor("authorities")
	String[] value() default { "ROLE_USER" };

	@AliasFor("value")
	String[] authorities() default { "ROLE_USER" };

	OpenIdClaims claims() default @OpenIdClaims();

	String tokenString() default "machin.truc.chose";

	Claims headers() default @Claims(stringClaims = @StringClaim(name = "alg", value = "none"));

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public static final class JwtAuthenticationTokenFactory extends AbstractAnnotatedAuthenticationBuilder<WithMockJwtAuth, JwtAuthenticationToken> {
		@Override
		public JwtAuthenticationToken authentication(WithMockJwtAuth annotation) {
			final var token = new OidcToken(super.claims(annotation.claims()));

			final var jwt = new Jwt(annotation.tokenString(), token.getIssuedAt(), token.getExpiresAt(), Claims.Token.of(annotation.headers()), token);

			return new JwtAuthenticationToken(jwt, super.authorities(annotation.authorities()));
		}
	}
}
