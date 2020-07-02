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
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdBuilder;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdBuilder.AddressClaim;
import com.c4_soft.springaddons.security.oauth2.test.Defaults;
import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.WithAddress;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockOidcId.Factory.class)
public @interface WithMockOidcId {

	@AliasFor("authorities")
	String[] value() default {};

	@AliasFor("value")
	String[] authorities() default {};

	String subject() default Defaults.SUBJECT;

	WithIDToken idToken() default @WithIDToken();

	WithStandardClaims standardClaims() default @WithStandardClaims();

	ClaimSet privateClaims() default @ClaimSet();

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public final class Factory extends OidcIdAuthenticationTokenTestingBuilder<Factory>
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
			feed(tokenBuilder, annotation.idToken());
			feed(tokenBuilder, annotation.standardClaims());
			for (IntClaim claim : annotation.privateClaims().intClaims()) {
				tokenBuilder.claim(claim.name(), claim.value());
			}
			for (LongClaim claim : annotation.privateClaims().longClaims()) {
				tokenBuilder.claim(claim.name(), claim.value());
			}
			for (StringClaim claim : annotation.privateClaims().stringClaims()) {
				tokenBuilder.claim(claim.name(), claim.value());
			}
			for (StringArrayClaim claim : annotation.privateClaims().stringArrayClaims()) {
				tokenBuilder.claim(claim.name(), claim.value());
			}
			tokenBuilder.subject(annotation.subject());

			if (annotation.authorities().length > 0) {
				authorities(annotation.authorities());
			}

			return build();
		}

		public static AddressClaim build(WithAddress addressAnnotation) {
			return new AddressClaim().country(nullIfEmpty(addressAnnotation.country()))
					.formatted(nullIfEmpty(addressAnnotation.formattedAddress()))
					.locality(nullIfEmpty(addressAnnotation.locality()))
					.postalCode(nullIfEmpty(addressAnnotation.postalCode()))
					.region(nullIfEmpty(addressAnnotation.region()))
					.streetAddress(nullIfEmpty(addressAnnotation.streetAddress()));
		}

		private static void feed(OidcIdBuilder token, WithIDToken tokenAnnotation) throws MalformedURLException {
			if (!StringUtils.isEmpty(tokenAnnotation.iss())) {
				token.issuer(new URL(tokenAnnotation.iss()));
			}
			token.subject(tokenAnnotation.sub());
			token.audience(Arrays.asList(tokenAnnotation.aud()));
			if (StringUtils.hasLength(tokenAnnotation.exp())) {
				token.expiresAt(Instant.parse(tokenAnnotation.exp()));
			}
			if (StringUtils.hasLength(tokenAnnotation.iat())) {
				token.issuedAt(Instant.parse(tokenAnnotation.iat()));
			}
			if (StringUtils.hasLength(tokenAnnotation.authTime())) {
				token.authTime(Instant.parse(tokenAnnotation.authTime()));
			}
			token.nonce(tokenAnnotation.nonce());
			token.acr(tokenAnnotation.acr());
			token.amr(Arrays.asList(tokenAnnotation.amr()));
			token.azp(tokenAnnotation.azp());
		}

		private static void feed(OidcIdBuilder token, WithStandardClaims tokenAnnotation) {
			token.address(build(tokenAnnotation.address()));
			token.birthdate(nullIfEmpty(tokenAnnotation.birthdate()));
			token.email(nullIfEmpty(tokenAnnotation.email()));
			token.emailVerified(tokenAnnotation.emailVerified());
			token.familyName(nullIfEmpty(tokenAnnotation.familyName()));
			token.gender(nullIfEmpty(tokenAnnotation.gender()));
			token.givenName(nullIfEmpty(tokenAnnotation.givenName()));
			token.locale(nullIfEmpty(tokenAnnotation.locale()));
			token.middleName(nullIfEmpty(tokenAnnotation.middleName()));
			token.name(nullIfEmpty(tokenAnnotation.name()));
			token.nickname(nullIfEmpty(tokenAnnotation.nickname()));
			token.phoneNumber(nullIfEmpty(tokenAnnotation.phoneNumber()));
			token.phoneNumberVerified(tokenAnnotation.phoneNumberVerified());
			token.preferredUsername(nullIfEmpty(tokenAnnotation.preferredUsername()));
			token.picture(nullIfEmpty(tokenAnnotation.picture()));
			token.profile(nullIfEmpty(tokenAnnotation.profile()));
			if (StringUtils.hasLength(tokenAnnotation.updatedAt())) {
				token.updatedAt(Instant.parse(tokenAnnotation.updatedAt()));
			}
			token.website(nullIfEmpty(tokenAnnotation.website()));
		}

		private static String nullIfEmpty(String str) {
			return StringUtils.isEmpty(str) ? null : str;
		}
	}
}
