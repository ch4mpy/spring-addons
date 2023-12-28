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
import java.util.Optional;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

import lombok.RequiredArgsConstructor;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link BearerTokenAuthentication}. Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockBearerTokenAuthentication(&#64;OpenIdClaims(
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
 * @see WithOpaqueToken &#64;WithOpaqueToken is an alternative using a JSON file as source for claims
 * @see WithMockAuthentication &#64;WithMockAuthentication is a convenient alternative when you just need to define name and authorities (and optionally the
 *      Authentication type)
 * @deprecated not as convenient in &#64;Parameterized tests as alternatives listed above and provide with less reliable consistency between introspected
 *             attributes and authorities
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

    @RequiredArgsConstructor
    public static final class AuthenticationFactory extends AbstractAnnotatedAuthenticationBuilder<WithMockBearerTokenAuthentication, Authentication> {

        private final Optional<OpaqueTokenAuthenticationConverter> opaqueTokenAuthenticationConverter;

        private final Optional<ReactiveOpaqueTokenAuthenticationConverter> reactiveOpaqueTokenAuthenticationConverter;

        @Override
        public Authentication authentication(WithMockBearerTokenAuthentication annotation) {
            final var claims = super.claims(annotation.attributes()).build();
            final var authorities = super.authorities(annotation.authorities(), annotation.value());
            final var principal = new OAuth2IntrospectionAuthenticatedPrincipal(claims.getName(), claims, authorities);

            return opaqueTokenAuthenticationConverter.map(c -> {
                final var auth = c.convert(annotation.bearerString(), principal);
                return auth;
            }).orElseGet(() -> reactiveOpaqueTokenAuthenticationConverter.map(c -> {
                final var auth = c.convert(annotation.bearerString(), principal).block();
                return auth;
            }).orElseGet(() -> {
                final var credentials = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    annotation.bearerString(),
                    claims.getAsInstant(JwtClaimNames.IAT),
                    claims.getAsInstant(JwtClaimNames.EXP));
                return new BearerTokenAuthentication(principal, credentials, principal.getAuthorities());
            }));
        }
    }
}
