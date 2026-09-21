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

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.AliasFor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.util.StringUtils;

import com.nimbusds.jwt.JWTClaimNames;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import reactor.core.publisher.Mono;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link Authentication} instantiated by the (Reactive)JwtAuthenticaionConverter in the security conf.
 * Usage on tests decorated with &#64;AutoConfigureAddonsSecurity or &#64;AutoConfigureAddonsWebSecurity::
 *
 * <pre>
 * &#64;Test
 * &#64;WithJwt("ch4mp_auth0.json")
 * public void test() {
 *     ...
 * }
 * </pre>
 *
 * For usage with &#64;ParameterizedTest, you'll need a {@link MethodSource &#64;MethodSource} in a test running with &#64;TestInstance(Lifecycle.PER_CLASS).
 * Authentication instance should be injected in the test with &#64;ParameterizedAuthentication.
 *
 * <pre>
 * &#64;Autowired
 * WithJwt.AuthenticationFactory authFactory;
 *
 * &#64;ParameterizedTest
 * &#64;MethodSource("authSource")
 * void givenUserIsPersona_whenGetGreet_thenReturnsGreeting(@ParameterizedAuthentication Authentication auth) {
 *     ...
 * }
 *
 * Stream&lt;AbstractAuthenticationToken&gt; authSource() {
 *     return authFactory.authenticationsFrom("ch4mp.json", "tonton-pirate.json");
 * }
 * </pre>
 *
 * If using spring-addons-oauth2-test without spring-addons-starter-oidc-test, you should explicitly import &#64;Import(AuthenticationFactoriesTestConf.class)
 * (otherwise, the &#64;Addons...Test will pull this configuration for you)
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithJwt.AuthenticationFactory.class)
public @interface WithJwt {
    @AliasFor("file")
    String value() default "";

    @AliasFor("value")
    String file() default "";

    String json() default "";

    String bearerString() default AuthenticationFactory.DEFAULT_BEARER;

    String headers() default AuthenticationFactory.DEFAULT_HEADERS;

    /**
     * The name of the JWT authentication converter bean to build the {@link Authentication} with.
     * When empty (default), the bean is chosen the way spring-addons-starter-oidc does for its
     * security filter-chain: the single {@code Converter<Jwt, ? extends AbstractAuthenticationToken>}
     * bean (or reactive counterpart), the {@code @Primary} one, or else the one named
     * {@code jwtAuthenticationConverter}. Several candidates without such a preference is an error.
     * Without any such bean, a default {@link JwtAuthenticationConverter} is used.
     */
    String authenticationConverterBeanName() default "";

    public static final class AuthenticationFactory implements WithSecurityContextFactory<WithJwt> {
        static final String DEFAULT_BEARER = "test.jwt.bearer";
        static final String DEFAULT_HEADERS = "{\"alg\": \"none\"}";
        static final String DEFAULT_CONVERTER_BEAN_NAME = "jwtAuthenticationConverter";
        static final ResolvableType SERVLET_CONVERTER_TYPE = ResolvableType
            .forType(new ParameterizedTypeReference<Converter<Jwt, ? extends AbstractAuthenticationToken>>() {});
        static final ResolvableType REACTIVE_CONVERTER_TYPE = ResolvableType
            .forType(new ParameterizedTypeReference<Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>>() {});

        private final AuthenticationConverterLookup<Converter<Jwt, ? extends AbstractAuthenticationToken>, Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>> converterLookup;

        private final Converter<Jwt, AbstractAuthenticationToken> defaultAuthenticationConverter = new JwtAuthenticationConverter();

        /**
         * @param beanFactory the test context, where the JWT authentication converter is looked up when an {@link Authentication} is built
         */
        @Autowired
        public AuthenticationFactory(ListableBeanFactory beanFactory) {
            this.converterLookup = new AuthenticationConverterLookup<>(beanFactory, SERVLET_CONVERTER_TYPE, REACTIVE_CONVERTER_TYPE, DEFAULT_CONVERTER_BEAN_NAME);
        }

        /**
         * @param jwtAuthenticationConverter the servlet converter to build authentications with, if any
         * @param reactiveJwtAuthenticationConverter the reactive converter to use when there is no servlet one
         * @deprecated the converter is now looked up in the test context: use
         *             {@link #AuthenticationFactory(ListableBeanFactory)} (the factory is auto-configured as a bean by
         *             {@code AuthenticationFactoriesTestConf})
         */
        @Deprecated
        public AuthenticationFactory(
            Optional<Converter<Jwt, ? extends AbstractAuthenticationToken>> jwtAuthenticationConverter,
            Optional<Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>> reactiveJwtAuthenticationConverter) {
          this.converterLookup = new AuthenticationConverterLookup<>(jwtAuthenticationConverter,
              reactiveJwtAuthenticationConverter);
        }

        @Override
        public SecurityContext createSecurityContext(WithJwt annotation) {
            final var auth = authentication(annotation);

            final var securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(auth);

            return securityContext;
        }

        /**
         * @param annotation Test annotation with reference to a classpath resource or a JSON string to get claims from (and optional JWT headers and Bearer
         *            string)
         * @return an {@link Authentication} instance built by the JWT authentication converter in security configuration
         */
        public AbstractAuthenticationToken authentication(WithJwt annotation) {
            final var headers = parseJson(annotation.headers());

            final var claims = new HashMap<String, Object>();
            if (StringUtils.hasText(annotation.value())) {
                claims.putAll(parseFile(annotation.value()));
            }
            if (StringUtils.hasText(annotation.file())) {
                claims.putAll(parseFile(annotation.file()));
            }
            if (StringUtils.hasText(annotation.json())) {
                claims.putAll(parseJson(annotation.json()));
            }

            return authentication(claims, headers, annotation.bearerString(), annotation.authenticationConverterBeanName());
        }

        /**
         * @param claims the test JWT claims
         * @param headers the test JWT headers
         * @param bearerString the test JWT Bearer String
         * @return an {@link Authentication} instance built by the JWT authentication converter in security configuration
         */
        public AbstractAuthenticationToken authentication(Map<String, Object> claims, Map<String, Object> headers, String bearerString) {
            return authentication(claims, headers, bearerString, "");
        }

        /**
         * @param claims the test JWT claims
         * @param headers the test JWT headers
         * @param bearerString the test JWT Bearer String
         * @param authenticationConverterBeanName the name of the JWT authentication converter bean to use, or an empty string to select it as
         *            documented on {@link WithJwt#authenticationConverterBeanName()}
         * @return an {@link Authentication} instance built by the JWT authentication converter in security configuration
         */
        @SuppressWarnings("null")
        public AbstractAuthenticationToken authentication(
                Map<String, Object> claims,
                Map<String, Object> headers,
                String bearerString,
                String authenticationConverterBeanName) {
            final var now = Instant.now();
            final var iat = Optional.ofNullable(toLong(claims.get(JWTClaimNames.ISSUED_AT))).map(Instant::ofEpochSecond).orElse(now);
            final var exp = Optional.ofNullable(toLong(claims.get(JWTClaimNames.EXPIRATION_TIME))).map(Instant::ofEpochSecond).orElse(now.plusSeconds(42));

            final var jwt = new Jwt(bearerString, iat, exp, headers, claims);

            return converterLookup.<AbstractAuthenticationToken>apply(authenticationConverterBeanName, c -> c.convert(jwt), c -> c.convert(jwt).block())
                .orElseGet(() -> defaultAuthenticationConverter.convert(jwt));
        }

        private Long toLong(Object claim) {
            if (claim == null) {
                return null;
            }
            if (claim instanceof Long l) {
                return l;
            }
            if (claim instanceof Integer i) {
                return i.longValue();
            }
            return null;
        }

        /**
         * Build an {@link Authentication} for each of the claim-sets provided as classpath resources (JSON file)
         *
         * @param classpathResources classpath resources to get JWT claims from
         * @return an stream of {@link Authentication} instances built by the JWT authentication converter in security configuration (using default JWT headers
         *         and Bearer String)
         */
        public Stream<AbstractAuthenticationToken> authenticationsFrom(String... classpathResources) {
            return Stream
                .of(classpathResources)
                .map(AuthenticationFactory::parseFile)
                .map(claims -> this.authentication(claims, parseJson(DEFAULT_HEADERS), DEFAULT_BEARER));
        }

        /**
         * Extracts the claim-set in a JSON file
         *
         * @param fileName the classpath location of the JSON file
         * @return the parsed claims, or an empty map when the input is blank
         */
        public static Map<String, Object> parseFile(String fileName) {
            if (!StringUtils.hasText(fileName)) {
                return Map.of();
            }

            InputStream cpRessource;
            try {
                cpRessource = new ClassPathResource(fileName).getInputStream();
            } catch (IOException e) {
                throw new RuntimeException("Failed to load classpath resource %s".formatted(fileName), e);
            }
            try {
                return new JSONParser(JSONParser.MODE_PERMISSIVE).parse(cpRessource, JSONObject.class);
            } catch (final ParseException | UnsupportedEncodingException e) {
                throw new RuntimeException("Invalid JWT payload in classpath resource %s".formatted(fileName));
            }
        }

        /**
         * Extracts the claim-set in a JSON String
         *
         * @param json the claim-set as a JSON string
         * @return the parsed claims, or an empty map when the input is blank
         */
        public static Map<String, Object> parseJson(String json) {
            if (!StringUtils.hasText(json)) {
                return Map.of();
            }
            try {
                return new JSONParser(JSONParser.MODE_PERMISSIVE).parse(json, JSONObject.class);
            } catch (final ParseException e) {
                throw new RuntimeException("Invalid JSON payload in @WithJwt");
            }
        }
    }
}
