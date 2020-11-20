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
import java.util.Optional;
import java.util.stream.Stream;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import com.c4_soft.springaddons.security.oauth2.test.annotations.ClaimSet;
import com.c4_soft.springaddons.security.oauth2.test.annotations.IdTokenClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OidcStandardClaims;
import com.c4_soft.springaddons.security.oauth2.test.keycloak.KeycloakAuthenticationTokenTestingBuilder;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link KeycloakAuthenticationToken}, the Keycloak default
 * {@link Authentication} impl
 *
 * Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockKeycloakAuth(
			authorities = { "USER", "AUTHORIZED_PERSONNEL" },
			id = &#64;IdTokenClaims(sub = "42"),
			oidc = &#64;OidcStandardClaims(
					email = "ch4mp@c4-soft.com",
					emailVerified = true,
					nickName = "Tonton-Pirate",
					preferredUsername = "ch4mpy"),
			otherClaims = &#64;ClaimSet(stringClaims = &#64;StringClaim(name = "foo", value = "bar")))
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
@WithSecurityContext(factory = WithMockKeycloakAuth.Factory.class)
public @interface WithMockKeycloakAuth {

	@AliasFor("authorities")
	String[] value() default { "offline_access", "uma_authorization" };

	@AliasFor("value")
	String[] authorities() default { "offline_access", "uma_authorization" };

	KeycloakAccessToken accessToken() default @KeycloakAccessToken();

	IdTokenClaims id() default @IdTokenClaims();

	OidcStandardClaims oidc() default @OidcStandardClaims();

	ClaimSet otherClaims() default @ClaimSet();

	boolean isInteractive() default false;

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public static final class Factory implements WithSecurityContextFactory<WithMockKeycloakAuth> {

		private final KeycloakAuthenticationTokenTestingBuilder<?> builder;

		@Autowired
		public Factory(Optional<GrantedAuthoritiesMapper> authoritiesMapper) {
			this.builder = new KeycloakAuthenticationTokenTestingBuilder<>(authoritiesMapper);
		}

		@Autowired(required = false)
		public void setKeycloakDeployment(KeycloakDeployment keycloakDeployment) {
			this.builder.keycloakDeployment(keycloakDeployment);
		}

		@Override
		public SecurityContext createSecurityContext(WithMockKeycloakAuth annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(authentication(annotation));

			return context;
		}

		public KeycloakAuthenticationToken authentication(WithMockKeycloakAuth annotation) {
			return builder.isIntercative(annotation.isInteractive())
					.accessToken(accessToken -> AccessTokenBuilderHelper.feed(accessToken, annotation))
					.idToken(
							idToken -> IDTokenBuilderHelper
									.feed(idToken, annotation.id(), annotation.oidc(), annotation.otherClaims()))
					.authorities(
							Stream.concat(
									Stream.of(annotation.authorities()),
									Stream.of(annotation.accessToken().realmAccess().roles())))
					.build();
		}
	}
}
