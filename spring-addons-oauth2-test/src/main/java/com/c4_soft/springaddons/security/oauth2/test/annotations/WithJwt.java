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

import lombok.RequiredArgsConstructor;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import reactor.core.publisher.Mono;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link Authentication} instantiated by the (Reactive)JwtAuthenticaionConverter
 * in the security conf. Usage on tests decorated with &#64;AutoConfigureAddonsSecurity or &#64;AutoConfigureAddonsWebSecurity::
 *
 * <pre>
 * &#64;Test
 * &#64;WithJwt("ch4mp_auth0.json")
 * public void test() {
 *     ...
 * }
 * </pre>
 *
 * For usage with &#64;ParameterizedTest, you'll need a {@link MethodSource &#64;MethodSource} in a test running with
 * &#64;TestInstance(Lifecycle.PER_CLASS). Authentication instance should be injected in the test with &#64;ParameterizedAuthentication.
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
 * If using spring-addons-oauth2-test without spring-addons-starter-oidc-test, you should explicitly import
 * &#64;Import(AuthenticationFactoriesTestConf.class) (otherwise, the &#64;Addons...Test will pull this configuration for you)
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

	@RequiredArgsConstructor
	public static final class AuthenticationFactory implements WithSecurityContextFactory<WithJwt> {
		static final String DEFAULT_BEARER = "test.jwt.bearer";
		static final String DEFAULT_HEADERS = "{\"alg\": \"none\"}";

		private final Optional<Converter<Jwt, ? extends AbstractAuthenticationToken>> jwtAuthenticationConverter;

		private final Optional<Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>> reactiveJwtAuthenticationConverter;

		private final Converter<Jwt, AbstractAuthenticationToken> defaultAuthenticationConverter = new JwtAuthenticationConverter();

		@Override
		public SecurityContext createSecurityContext(WithJwt annotation) {
			final var auth = authentication(annotation);

			final var securityContext = SecurityContextHolder.createEmptyContext();
			securityContext.setAuthentication(auth);

			return securityContext;
		}

		/**
		 * @param  annotation Test annotation with reference to a classpath resource or a JSON string to get claims from (and optional JWT headers
		 *                    and Bearer string)
		 * @return            an {@link Authentication} instance built by the JWT authentication converter in security configuration
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

			return authentication(claims, headers, annotation.bearerString());
		}

		/**
		 * @param  claims       the test JWT claims
		 * @param  headers      the test JWT headers
		 * @param  bearerString the test JWT Bearer String
		 * @return              an {@link Authentication} instance built by the JWT authentication converter in security configuration
		 */
		@SuppressWarnings("null")
		public AbstractAuthenticationToken authentication(Map<String, Object> claims, Map<String, Object> headers, String bearerString) {
			final var now = Instant.now();
			final var iat = Optional.ofNullable((Integer) claims.get(JWTClaimNames.ISSUED_AT)).map(Instant::ofEpochSecond).orElse(now);
			final var exp = Optional.ofNullable((Integer) claims.get(JWTClaimNames.EXPIRATION_TIME)).map(Instant::ofEpochSecond).orElse(now.plusSeconds(42));

			final var jwt = new Jwt(bearerString, iat, exp, headers, claims);

			return jwtAuthenticationConverter.map(c -> {
				final AbstractAuthenticationToken auth = c.convert(jwt);
				return auth;
			}).orElseGet(() -> reactiveJwtAuthenticationConverter.map(c -> {
				final AbstractAuthenticationToken auth = c.convert(jwt).block();
				return auth;
			}).orElse(defaultAuthenticationConverter.convert(jwt)));
		}

		/**
		 * Build an {@link Authentication} for each of the claim-sets provided as classpath resources (JSON file)
		 *
		 * @param  classpathResources classpath resources to get JWT claims from
		 * @return                    an stream of {@link Authentication} instances built by the JWT authentication converter in security
		 *                            configuration (using default JWT headers and Bearer String)
		 */
		public Stream<AbstractAuthenticationToken> authenticationsFrom(String... classpathResources) {
			return Stream.of(classpathResources).map(AuthenticationFactory::parseFile)
					.map(claims -> this.authentication(claims, parseJson(DEFAULT_HEADERS), DEFAULT_BEARER));
		}

		/**
		 * Extracts the claim-set in a JSON file
		 *
		 * @param  fileName
		 * @return
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
		 * @param  json
		 * @return
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
