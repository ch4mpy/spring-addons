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
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.annotation.AliasFor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

/**
 * Annotation to setup test {@link SecurityContext} with an {@link Authentication} instantiated by the (Reactive)OpaqueTokenAuthenticationConverter in the
 * security conf. Usage on tests decorated with &#64;AutoConfigureAddonsSecurity or &#64;AutoConfigureAddonsWebSecurity::
 *
 * <pre>
 * &#64;Test
 * &#64;WithOpaqueToken("ch4mp_auth0.json")
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
 * WithOpaqueToken.AuthenticationFactory authFactory;
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
@WithSecurityContext(factory = WithOpaqueToken.AuthenticationFactory.class)
public @interface WithOpaqueToken {
	@AliasFor("file")
	String value() default "";

	@AliasFor("value")
	String file() default "";

	String json() default "";

	String bearerString() default AuthenticationFactory.DEFAULT_BEARER;

	@RequiredArgsConstructor
	public static final class AuthenticationFactory implements WithSecurityContextFactory<WithOpaqueToken> {
		static final String DEFAULT_BEARER = "test.jwt.bearer";

		private final Optional<OpaqueTokenAuthenticationConverter> opaqueTokenAuthenticationConverter;

		private final Optional<ReactiveOpaqueTokenAuthenticationConverter> reactiveOpaqueTokenAuthenticationConverter;

		@Override
		public SecurityContext createSecurityContext(WithOpaqueToken annotation) {
			final var auth = authentication(annotation);

			final var securityContext = SecurityContextHolder.createEmptyContext();
			securityContext.setAuthentication(auth);

			return securityContext;
		}

		/**
		 * @param  annotation Test annotation with reference to a classpath resource or a JSON string to get claims from (and optional JWT headers and Bearer
		 *                    string)
		 * @return            an {@link Authentication} instance built by the opaque token authentication converter in security configuration
		 */
		public Authentication authentication(WithOpaqueToken annotation) {
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

			return authentication(claims, annotation.bearerString());
		}

		/**
		 * @param  claims       the test user claims
		 * @param  bearerString the test opaque token Bearer String
		 * @return              an {@link Authentication} instance built by the opaque token authentication converter in security configuration
		 */
		public Authentication authentication(Map<String, Object> claims, String bearerString) {
			final var principal = new OAuth2AuthenticatedPrincipal() {

				@Override
				public String getName() {
					return null;
				}

				@Override
				public Collection<? extends GrantedAuthority> getAuthorities() {
					return null;
				}

				@Override
				public Map<String, Object> getAttributes() {
					return claims;
				}
			};

			return opaqueTokenAuthenticationConverter.map(c -> {
				final var auth = c.convert(bearerString, principal);
				return auth;
			}).orElseGet(() -> reactiveOpaqueTokenAuthenticationConverter.map(c -> {
				final var auth = c.convert(bearerString, principal).block();
				return auth;
			}).orElseGet(() -> {
				Instant iat = principal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT);
				Instant exp = principal.getAttribute(OAuth2TokenIntrospectionClaimNames.EXP);
				OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, bearerString, iat, exp);
				return new BearerTokenAuthentication(principal, accessToken, principal.getAuthorities());
			}));
		}

		/**
		 * Build an {@link Authentication} for each of the claim-sets provided as classpath resources (JSON file)
		 *
		 * @param  classpathResources classpath resources to get user claims from
		 * @return                    a stream of {@link Authentication} instances built by the opaque token authentication converter in security configuration
		 *                            (using default Bearer String)
		 */
		public Stream<Authentication> authenticationsFrom(String... classpathResources) {
			return Stream.of(classpathResources).map(AuthenticationFactory::parseFile).map(claims -> this.authentication(claims, DEFAULT_BEARER));
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
				throw new RuntimeException("Invalid user claims payload in classpath resource %s".formatted(fileName));
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
				throw new RuntimeException("Invalid JSON payload in @WithOpaqueToken");
			}
		}
	}
}
