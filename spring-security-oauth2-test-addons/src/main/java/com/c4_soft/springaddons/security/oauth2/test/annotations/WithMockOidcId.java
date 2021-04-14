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
package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.MalformedURLException;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;
import com.c4_soft.springaddons.security.oauth2.test.OidcIdAuthenticationTokenTestingBuilder;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link OidcIdAuthenticationToken}.
 *
 * Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockOidcId(
			authorities = { "USER", "AUTHORIZED_PERSONNEL" },
			id = &#64;IdTokenClaims(sub = "42"),
			oidc = &#64;OidcStandardClaims(
					email = "ch4mp@c4-soft.com",
					emailVerified = true,
					nickName = "Tonton-Pirate",
					preferredUsername = "ch4mpy"),
			privateClaims = &#64;ClaimSet(stringClaims = &#64;StringClaim(name = "foo", value = "bar")))
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
@WithSecurityContext(factory = WithMockOidcId.OidcIdAuthenticationTokenFactory.class)
public @interface WithMockOidcId {

	@AliasFor("authorities")
	String[] value() default {};

	@AliasFor("value")
	String[] authorities() default {};

	IdTokenClaims id() default @IdTokenClaims();

	OidcStandardClaims oidc() default @OidcStandardClaims();

	ClaimSet privateClaims() default @ClaimSet();

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public final class OidcIdAuthenticationTokenFactory
			extends
			OidcIdAuthenticationTokenTestingBuilder<OidcIdAuthenticationTokenFactory>
			implements
			WithSecurityContextFactory<WithMockOidcId> {

		@Override
		public SecurityContext createSecurityContext(WithMockOidcId annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			try {
				context.setAuthentication(authentication(annotation));
			} catch (MalformedURLException e) {
				throw new RuntimeException(e);
			}

			return context;
		}

		public OidcIdAuthenticationToken authentication(WithMockOidcId annotation) throws MalformedURLException {
			IdTokenBuilderHelper.feed(tokenBuilder, annotation.id());
			OidcIdBuilderHelper.feed(tokenBuilder, annotation.oidc());
			for (IntClaim claim : annotation.privateClaims().intClaims()) {
				tokenBuilder.claim(claim.name(), claim.value());
			}
			for (var claim : annotation.privateClaims().longClaims()) {
				tokenBuilder.claim(claim.name(), claim.value());
			}
			for (var claim : annotation.privateClaims().stringClaims()) {
				tokenBuilder.claim(claim.name(), claim.value());
			}
			for (var claim : annotation.privateClaims().stringArrayClaims()) {
				tokenBuilder.claim(claim.name(), claim.value());
			}
			for (var claim : annotation.privateClaims().jsonObjectClaims()) {
				tokenBuilder.claim(claim.name(), JsonObjectClaim.Support.parse(claim));
			}
			for (var claim : annotation.privateClaims().jsonArrayClaims()) {
				tokenBuilder.claim(claim.name(), JsonArrayClaim.Support.parse(claim));
			}

			if (annotation.authorities().length > 0) {
				authorities(annotation.authorities());
			}

			return build();
		}
	}
}
