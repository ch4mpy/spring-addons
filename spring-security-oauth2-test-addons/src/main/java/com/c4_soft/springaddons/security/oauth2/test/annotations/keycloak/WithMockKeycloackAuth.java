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
package com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.time.Instant;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AddressClaimSet;
import org.keycloak.representations.IDToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.test.Defaults;
import com.c4_soft.springaddons.security.oauth2.test.keycloak.KeycloakAuthenticationTokenTestingBuilder;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link KeycloakAuthenticationToken}, the Keycloak default
 * {@link Authentication} impl
 *
 * Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockKeycloackAuth({"ROLE_USER", "ROLE_ADMIN"})
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
@WithSecurityContext(factory = WithMockKeycloackAuth.Factory.class)
public @interface WithMockKeycloackAuth {

	@AliasFor("roles")
	String[] value() default { "offline_access", "uma_authorization" };

	@AliasFor("value")
	String[] roles() default { "offline_access", "uma_authorization" };

	boolean isInteractive() default true;

	String name() default Defaults.AUTH_NAME;

	WithAccessToken accessToken() default @WithAccessToken();

	WithKeycloackIDToken idToken() default @WithKeycloackIDToken();

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public final class Factory implements WithSecurityContextFactory<WithMockKeycloackAuth> {

		private final KeycloakAuthenticationTokenTestingBuilder<?> builder;

		public Factory() {
			this.builder = new KeycloakAuthenticationTokenTestingBuilder<>();
		}

		@Autowired(required = false)
		public void setKeycloakDeployment(KeycloakDeployment keycloakDeployment) {
			this.builder.keycloakDeployment(keycloakDeployment);
		}

		@Override
		public SecurityContext createSecurityContext(WithMockKeycloackAuth annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(authentication(annotation));

			return context;
		}

		public KeycloakAuthenticationToken authentication(WithMockKeycloackAuth annotation) {
			return builder.roles(annotation.roles())
					.name(annotation.name())
					.isIntercative(annotation.isInteractive())
					.accessToken(token -> feed(token, annotation.accessToken()))
					.idToken(token -> feed(token, annotation.idToken()))
					.build();
		}

		public static AddressClaimSet build(WithAddress addressAnnotation) {
			final var address = new AddressClaimSet();
			address.setCountry(nullIfEmpty(addressAnnotation.country()));
			address.setFormattedAddress(nullIfEmpty(addressAnnotation.formattedAddress()));
			address.setLocality(nullIfEmpty(addressAnnotation.locality()));
			address.setPostalCode(nullIfEmpty(addressAnnotation.postalCode()));
			address.setRegion(nullIfEmpty(addressAnnotation.region()));
			address.setStreetAddress(nullIfEmpty(addressAnnotation.streetAddress()));
			return address;
		}

		private static void feed(IDToken token, WithKeycloackIDToken tokenAnnotation) {
			token.setAccessTokenHash(nullIfEmpty(tokenAnnotation.accessTokenHash()));
			token.setAcr(nullIfEmpty(tokenAnnotation.acr()));
			token.setAddress(build(tokenAnnotation.address()));
			if (StringUtils.hasLength(tokenAnnotation.authTime())) {
				token.setAuthTime((int) Instant.parse(tokenAnnotation.authTime()).getEpochSecond());
			}
			token.setBirthdate(nullIfEmpty(tokenAnnotation.birthdate()));
			token.setClaimsLocales(nullIfEmpty(tokenAnnotation.claimsLocales()));
			token.setCodeHash(nullIfEmpty(tokenAnnotation.codeHash()));
			token.setEmail(nullIfEmpty(tokenAnnotation.email()));
			token.setEmailVerified(tokenAnnotation.emailVerified());
			token.setFamilyName(nullIfEmpty(tokenAnnotation.familyName()));
			token.setGender(nullIfEmpty(tokenAnnotation.gender()));
			token.setGivenName(nullIfEmpty(tokenAnnotation.givenName()));
			token.setLocale(nullIfEmpty(tokenAnnotation.locale()));
			token.setMiddleName(nullIfEmpty(tokenAnnotation.middleName()));
			token.setName(nullIfEmpty(tokenAnnotation.name()));
			token.setNickName(nullIfEmpty(tokenAnnotation.nickName()));
			token.setNonce(nullIfEmpty(tokenAnnotation.nonce()));
			token.setPhoneNumber(nullIfEmpty(tokenAnnotation.phoneNumber()));
			token.setPhoneNumberVerified(tokenAnnotation.phoneNumberVerified());
			token.setPreferredUsername(nullIfEmpty(tokenAnnotation.preferredUsername()));
			token.setPicture(nullIfEmpty(tokenAnnotation.picture()));
			token.setProfile(nullIfEmpty(tokenAnnotation.profile()));
			token.setSessionState(nullIfEmpty(tokenAnnotation.sessionState()));
			if (StringUtils.hasLength(tokenAnnotation.updatedAt())) {
				token.setUpdatedAt(Instant.parse(tokenAnnotation.updatedAt()).getEpochSecond());
			}
			token.setWebsite(nullIfEmpty(tokenAnnotation.website()));
		}

		private static void feed(AccessToken token, WithAccessToken tokenAnnotation) {
			token.setAccessTokenHash(nullIfEmpty(tokenAnnotation.accessTokenHash()));
			token.setAcr(nullIfEmpty(tokenAnnotation.acr()));
			token.setAddress(build(tokenAnnotation.address()));
			token.setAuthTime(tokenAnnotation.authTime());
			token.setBirthdate(nullIfEmpty(tokenAnnotation.birthdate()));
			token.setClaimsLocales(nullIfEmpty(tokenAnnotation.claimsLocales()));
			token.setCodeHash(nullIfEmpty(tokenAnnotation.codeHash()));
			token.setEmail(nullIfEmpty(tokenAnnotation.email()));
			token.setEmailVerified(tokenAnnotation.emailVerified());
			token.setFamilyName(nullIfEmpty(tokenAnnotation.familyName()));
			token.setGender(nullIfEmpty(tokenAnnotation.gender()));
			token.setGivenName(nullIfEmpty(tokenAnnotation.givenName()));
			token.setLocale(nullIfEmpty(tokenAnnotation.locale()));
			token.setMiddleName(nullIfEmpty(tokenAnnotation.middleName()));
			token.setName(nullIfEmpty(tokenAnnotation.name()));
			token.setNickName(nullIfEmpty(tokenAnnotation.nickName()));
			token.setNonce(nullIfEmpty(tokenAnnotation.nonce()));
			token.setPhoneNumber(nullIfEmpty(tokenAnnotation.phoneNumber()));
			token.setPhoneNumberVerified(tokenAnnotation.phoneNumberVerified());
			token.setPicture(nullIfEmpty(tokenAnnotation.picture()));
			token.setProfile(nullIfEmpty(tokenAnnotation.profile()));
			token.setSessionState(nullIfEmpty(tokenAnnotation.sessionState()));
			token.setUpdatedAt(tokenAnnotation.updatedAt());
			token.setWebsite(nullIfEmpty(tokenAnnotation.website()));
			token.setScope(nullIfEmpty(tokenAnnotation.scope()));
		}

		private static String nullIfEmpty(String str) {
			return StringUtils.isEmpty(str) ? null : str;
		}
	}
}
