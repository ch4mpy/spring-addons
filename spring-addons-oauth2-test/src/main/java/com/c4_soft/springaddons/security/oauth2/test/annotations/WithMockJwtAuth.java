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
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link JwtAuthenticationToken}. Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockJwtAuth(&#64;OpenIdClaims(sub = "42"))
 * public void test() {
 *     ...
 * }
 * </pre>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @see WithJwt &#64;WithJwt is an alternative using a JSON file as source for claims
 * @see WithMockAuthentication &#64;WithMockAuthentication is a convenient alternative when you just need to define name and authorities (and optionally the
 *      Authentication type)
 * @deprecated not as convenient in &#64;Parameterized tests as alternatives listed above and provide with less reliable consistency between claims and
 *             authorities
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockJwtAuth.JwtAuthenticationTokenFactory.class)
public @interface WithMockJwtAuth {

    @AliasFor("claims")
    OpenIdClaims value() default @OpenIdClaims();

    @AliasFor("value")
    OpenIdClaims claims() default @OpenIdClaims();

    String tokenString() default "machin.truc.chose";

    Claims headers() default @Claims(stringClaims = @StringClaim(name = "alg", value = "none"));

    @AliasFor(annotation = WithSecurityContext.class)
    TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

    @RequiredArgsConstructor
    public static final class JwtAuthenticationTokenFactory extends AbstractAnnotatedAuthenticationBuilder<WithMockJwtAuth, AbstractAuthenticationToken> {

        private final Optional<Converter<Jwt, ? extends AbstractAuthenticationToken>> jwtAuthenticationConverter;

        private final Optional<Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>> reactiveJwtAuthenticationConverter;

        @Override
        public AbstractAuthenticationToken authentication(WithMockJwtAuth annotation) {
            final var token = super.claims(annotation.claims()).build();

            final var jwt = new Jwt(annotation.tokenString(), token.getIssuedAt(), token.getExpiresAt(), Claims.Token.of(annotation.headers()), token);

            return jwtAuthenticationConverter.map(c -> {
                final AbstractAuthenticationToken auth = c.convert(jwt);
                return auth;
            }).orElseGet(() -> reactiveJwtAuthenticationConverter.map(c -> {
                final AbstractAuthenticationToken auth = c.convert(jwt).block();
                return auth;
            }).orElseGet(() -> {
                final var converter = new JwtAuthenticationConverter();
                converter.setPrincipalClaimName(annotation.claims().usernameClaim());
                return converter.convert(jwt);
            }));
        }
    }
}
