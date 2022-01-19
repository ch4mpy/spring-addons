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
package com.c4_soft.springaddons.samples.webmvc.custom;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.AbstractAnnotatedAuthenticationBuilder;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link OidcAuthentication}. Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithCustomAuth(
 *         authorities = { "USER", "AUTHORIZED_PERSONNEL" },
 *         claims = @OpenIdClaims(
 *         	   sub = "42",
 *             email = "ch4mp@c4-soft.com",
 *             emailVerified = true,
 *             nickName = "Tonton-Pirate",
 *             preferredUsername = "ch4mpy"),
 *         grants = {
 *             &#64;Grant(proxiedUserSubject = "1111", proxyIds = { "1", "2" }),
 *             &#64;Grant(proxiedUserSubject = "1112", proxyIds = { "1" }) })
 * public void test() {
 *     ...
 * }
 * </pre>
 *
 * or
 *
 * <pre>
 * &#64;Test
 * &#64;WithCustomAuth(
 *         authorities = { "USER", "AUTHORIZED_PERSONNEL" },
 *         claims = &#64;OpenIdClaims(
 *             sub = "42",
 *             email = "ch4mp@c4-soft.com",
 *             emailVerified = true,
 *             nickName = "Tonton-Pirate",
 *             preferredUsername = "ch4mpy",
 *             otherClaims = &#64;ClaimSet(stringClaims = &#64;jsonObjectClaims(name = "grants", value = "{'1111': [1, 2], '1113': [1]}"))))
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
@WithSecurityContext(factory = WithCustomAuth.CustomAuthFactory.class)
public @interface WithCustomAuth {

	@AliasFor("authorities")
	String[] value() default { "ROLE_USER" };

	@AliasFor("value")
	String[] authorities() default { "ROLE_USER" };

	Grant[] grants() default {};

	OpenIdClaims claims() default @OpenIdClaims();

	String bearerString() default "machin.truc.chose";

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	public static @interface Grant {
		String proxiedUserSubject();

		long[] proxyIds();
	}

	public static final class CustomAuthFactory extends AbstractAnnotatedAuthenticationBuilder<WithCustomAuth, OidcAuthentication<CustomOidcToken>> {
		@Override
		public OidcAuthentication<CustomOidcToken> authentication(WithCustomAuth annotation) {
			final OidcToken oidcClaims = OpenIdClaims.Token.of(annotation.claims());

			// create a copy of OIDC claim-set and add grants to it
			final Map<String, Object> allClaims = new HashMap<>(oidcClaims);
			allClaims.putAll(oidcClaims);
			allClaims.putIfAbsent("grants", new HashMap<String, Set<Long>>());
			@SuppressWarnings("unchecked")
			final Map<String, Set<Long>> grants = (Map<String, Set<Long>>) allClaims.get("grants");
			for (final Grant grant : annotation.grants()) {
				final Set<Long> ids = new HashSet<>(grant.proxyIds().length);
				for (final Long id : grant.proxyIds()) {
					ids.add(id);
				}
				grants.put(grant.proxiedUserSubject(), ids);
			}

			return new OidcAuthentication<>(new CustomOidcToken(allClaims), authorities(annotation.authorities()), annotation.bearerString());
		}
	}
}
