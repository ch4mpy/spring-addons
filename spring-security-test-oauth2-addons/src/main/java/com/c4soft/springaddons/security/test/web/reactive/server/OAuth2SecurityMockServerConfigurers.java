/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.c4soft.springaddons.security.test.web.reactive.server;

import java.util.Collection;
import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;

import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2Authentication;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesIntrospectionClaimSet;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;
import com.c4soft.springaddons.security.test.support.TestingAuthenticationTokenBuilder;
import com.c4soft.springaddons.security.test.support.introspection.IntrospectionClaimSetAuthenticationTestingBuilder;
import com.c4soft.springaddons.security.test.support.introspection.OAuth2IntrospectionAuthenticationTokenTestingBuilder;
import com.c4soft.springaddons.security.test.support.jwt.JwtAuthenticationTokenTestingBuilder;
import com.c4soft.springaddons.security.test.support.jwt.JwtClaimSetAuthenticationTestingBuilder;
import com.c4soft.springaddons.security.test.support.openid.OAuth2LoginAuthenticationTokenTestingBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2SecurityMockServerConfigurers {

	/**
	 * <p>
	 * Set-up WebTestClient security-context with an {@link OAuth2Authentication}&lt;{@link WithAuthoritiesJwtClaimSet}&gt;
	 * </p>
	 *
	 * Sample usage (see JwtClaimSetAuthenticationConfigurerTests for more):
	 * <pre>
	 * final var authConfigurer = mockJwtClaimSet(claims -&gt; claims
	 *     .subject("ch4mpy")
	 *     .authorities("message:read"));
	 *
	 * WebTestClient.bindToController(new TestController())
	 *     .webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
	 *     .apply(springSecurity())
	 *     .configureClient()
	 *     .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
	 *     .apply(authConfigurer)
	 *     .build()
	 *     .get().uri("/jwt-claims").exchange()
	 *     .expectStatus().isOk()
	 *     .expectBody(String.class).isEqualTo(
	 *         "Hello, ch4mpy! You are successfully authenticated and granted with [sub =&gt; ch4mpy, authorities =&gt; [message:read]] claims using a JSON Web Token.");
	 * </pre>
	 *
	 * @param claimsConsumer configures JWT claim-set
	 * @return JwtClaimSetAuthenticationConfigurer to further configure
	 */
	public static JwtClaimSetAuthenticationConfigurer mockJwtClaimSet(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
		return new JwtClaimSetAuthenticationConfigurer(claimsConsumer);
	}

	/**
	 * <p>
	 * Set-up a {@link OAuth2Authentication}&lt;{@link WithAuthoritiesJwtClaimSet}&gt;
	 * with "user" as subject and ["ROLE_USER"] as authorities in WebTestClient security-context.
	 * </p>
	 *
	 * Sample usage (see JwtClaimSetAuthenticationConfigurerTests for more):
	 * <pre>
	 * WebTestClient.bindToController(new TestController())
	 * 		.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
	 * 		.apply(springSecurity())
	 * 		.configureClient()
	 * 		.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
	 * 		.apply(mockJwtClaimSet())
	 * 		.build()
	 * 		.get().uri("/jwt-claims").exchange()
	 * 		.expectStatus().isOk()
	 * 		.expectBody(String.class).isEqualTo(
	 * 				"Hello, user! You are successfully authenticated and granted with [sub =&gt; ch4mpy, authorities =&gt; [ROLE_USER]] claims using a JSON Web Token.");
	 * </pre>
	 *
	 * @return JwtClaimSetAuthenticationConfigurer to further configure
	 */
	public static JwtClaimSetAuthenticationConfigurer mockJwtClaimSet() {
		return new JwtClaimSetAuthenticationConfigurer(claims -> {});
	}

	/**
	 * <p>
	 * Set-up WebTestClient security-context with an {@link OAuth2Authentication}&lt;{@link WithAuthoritiesIntrospectionClaimSet}&gt;
	 * </p>
	 *
	 * Sample usage (see IntrospectionClaimSetAuthenticationConfigurerTests for more):
	 * <pre>
	 * final var authConfigurer = mockIntrospectionClaimSet(claims -&gt; claims
	 *     .subject("ch4mpy")
	 *     .authorities("message:read"));
	 *
	 * WebTestClient.bindToController(new TestController())
	 *     .webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
	 *     .apply(springSecurity())
	 *     .configureClient()
	 *     .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
	 *     .apply(authConfigurer)
	 *     .build()
	 *     .get().uri("/introspection-claims").exchange()
	 *     .expectStatus().isOk()
	 *     .expectBody(String.class).isEqualTo(
	 *         "Hello, ch4mpy! You are successfully authenticated and granted with [sub =&gt; ch4mpy, authorities =&gt; [message:read]] claims using a JSON Web Token.");
	 * </pre>
	 *
	 * @param claimsConsumer configures Introspection claim-set
	 * @return IntrospectionClaimSetAuthenticationConfigurer to further configure
	 */
	public static IntrospectionClaimSetAuthenticationConfigurer mockIntrospectionClaimSet(Consumer<WithAuthoritiesIntrospectionClaimSet.Builder<?>> claimsConsumer) {
		return new IntrospectionClaimSetAuthenticationConfigurer(claimsConsumer);
	}

	/**
	 * <p>
	 * Set-up WebTestClient security-context with an {@link OAuth2Authentication}&lt;{@link WithAuthoritiesIntrospectionClaimSet}&gt;
	 * </p>
	 *
	 * Sample usage (see IntrospectionClaimSetAuthenticationConfigurerTests for more):
	 * <pre>
	 * WebTestClient.bindToController(new TestController())
	 *     .webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
	 *     .apply(springSecurity())
	 *     .configureClient()
	 *     .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
	 *     .apply(mockIntrospectionClaimSet())
	 *     .build()
	 *     .get().uri("/introspection-claims").exchange()
	 *     .expectStatus().isOk()
	 *     .expectBody(String.class).isEqualTo(
	 *         "Hello, user! You are successfully authenticated and granted with [sub =&gt; ch4mpy, authorities =&gt; [ROLE_USER]] claims using a JSON Web Token.");
	 * </pre>
	 *
	 * @return IntrospectionClaimSetAuthenticationConfigurer to further configure
	 */
	public static IntrospectionClaimSetAuthenticationConfigurer mockIntrospectionClaimSet() {
		return new IntrospectionClaimSetAuthenticationConfigurer(claims -> {});
	}

	/**
	 * <p>
	 * Set-up WebTestClient security-context with an {@link JwtAuthenticationToken};
	 * </p>
	 *
	 * Sample usage (see JwtAuthenticationTokenConfigurerTests for more):
	 * <pre>
	 * &#64;Test
	 * public void demo() {
	 *     WebTestClient.bindToController(new TestController())
	 *         .webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
	 *         .apply(springSecurity())
	 *         .configureClient()
	 *         .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
	 *         .apply(mockJwt(new JwtGrantedAuthoritiesConverter())).build()
	 *         .get().uri("/greet").exchange()
	 *         .expectStatus().isOk()
	 *         .expectBody(String.class).isEqualTo(String.format("Hello, %s!", Defaults.AUTH_NAME));
	 *
	 *     WebTestClient.bindToController(new TestController())
	 *         .webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
	 *         .apply(springSecurity())
	 *         .configureClient()
	 *         .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
	 *         .apply(mockJwt(new JwtGrantedAuthoritiesConverter())
	 *             .name("ch4mpy")
	 *             .scopes("message:read"))
	 *         .build()
	 *         .get().uri("/jwt").exchange()
	 *         .expectStatus().isOk()
	 *     .    expectBody(String.class).isEqualTo(
	 *     		    "Hello, ch4mpy! You are successfully authenticated and granted with [message:read] scopes using a JSON Web Token.");
	 * }
	 * </pre>
	 *
	 * @param authoritiesConverter Spring default one is {@link JwtGrantedAuthoritiesConverter}
	 * @return WebTestClient configurer (mutator) to further configure
	 */
	public static JwtAuthenticationTokenConfigurer mockJwt(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		return new JwtAuthenticationTokenConfigurer(authoritiesConverter);
	}

	/**
	 * <p>
	 * Set-up WebTestClient security-context with an {@link JwtAuthenticationToken} and default authorities converter.
	 * Shortcut for {@code mockJwt(new JwtGrantedAuthoritiesConverter())}
	 * </p>
	 *
	 * @return WebTestClient configurer (mutator) to further configure
	 */
	public static JwtAuthenticationTokenConfigurer mockJwt() {
		return mockJwt(new JwtGrantedAuthoritiesConverter());
	}

	/**
	 * <p>
	 * Set-up WebTestClient security-context with an {@link OAuth2IntrospectionAuthenticationToken}.
	 * </p>
	 *
	 * Sample usage (see OAuth2IntrospectionAuthenticationTokenConfigurerTests for more):
	 * <pre>
	&#64;Test
	public void testDefaultAccessTokenConfigurerSetNameToUser() {
		WebTestClient.bindToController(new TestController())
				.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
				.apply(springSecurity())
				.configureClient()
				.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
				.apply(mockIntrospectedToken())
				.build()
				.get().uri("/greet").exchange()
				.expectBody(String.class).isEqualTo("Hello, user!");

		WebTestClient.bindToController(new TestController())
				.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
				.apply(springSecurity())
				.configureClient()
				.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
				.apply(mockIntrospectedToken().token(accessToken -&gt; accessToken
				        .attributes(claims -&gt; claims
						        .username("ch4mpy")
						        .scope("message:read"))))
				.build()
				.get().uri("/introspection").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(
						"Hello, ch4mpy! You are successfully authenticated and granted with [message:read] scopes using a bearer token and OAuth2 introspection endpoint.");
	}
	 * </pre>
	 *
	 * @return WebTestClient configurer (mutator) to further configure
	 */
	public static OAuth2IntrospectionAuthenticationTokenConfigurer mockIntrospectedToken() {
		return new OAuth2IntrospectionAuthenticationTokenConfigurer();
	}

	public static OAuth2LoginAuthenticationTokenConfigurer mockOidcId(AuthorizationGrantType requestAuthorizationGrantType) {
		return new OAuth2LoginAuthenticationTokenConfigurer(requestAuthorizationGrantType);
	}

	public static OAuth2LoginAuthenticationTokenConfigurer mockOidcId() {
		return new OAuth2LoginAuthenticationTokenConfigurer();
	}

	public static TestingAuthenticationTokenConfigurer mockTestingToken() {
		return new TestingAuthenticationTokenConfigurer();
	}


	public static class JwtAuthenticationTokenConfigurer extends JwtAuthenticationTokenTestingBuilder<JwtAuthenticationTokenConfigurer>
			implements
			AuthenticationConfigurer<JwtAuthenticationToken> {

		public JwtAuthenticationTokenConfigurer(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			super(authoritiesConverter);
		}
	}

	public static class JwtClaimSetAuthenticationConfigurer extends JwtClaimSetAuthenticationTestingBuilder
			implements AuthenticationConfigurer<OAuth2Authentication<WithAuthoritiesJwtClaimSet>> {
		public JwtClaimSetAuthenticationConfigurer(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
			super(claimsConsumer);
		}
	}

	public static class IntrospectionClaimSetAuthenticationConfigurer extends IntrospectionClaimSetAuthenticationTestingBuilder
			implements AuthenticationConfigurer<OAuth2Authentication<WithAuthoritiesIntrospectionClaimSet>> {
		public IntrospectionClaimSetAuthenticationConfigurer(Consumer<WithAuthoritiesIntrospectionClaimSet.Builder<?>> claimsConsumer) {
			super(claimsConsumer);
		}
	}

	public static class OAuth2IntrospectionAuthenticationTokenConfigurer
			extends
			OAuth2IntrospectionAuthenticationTokenTestingBuilder<OAuth2IntrospectionAuthenticationTokenConfigurer>
			implements
			AuthenticationConfigurer<OAuth2IntrospectionAuthenticationToken> {
	}

	public static class OAuth2LoginAuthenticationTokenConfigurer extends OAuth2LoginAuthenticationTokenTestingBuilder<OAuth2LoginAuthenticationTokenConfigurer>
			implements
			AuthenticationConfigurer<OAuth2LoginAuthenticationToken> {

		public OAuth2LoginAuthenticationTokenConfigurer(AuthorizationGrantType requestAuthorizationGrantType) {
			super(requestAuthorizationGrantType);
		}

		public OAuth2LoginAuthenticationTokenConfigurer() {
			super();
		}
	}

	public static class TestingAuthenticationTokenConfigurer extends TestingAuthenticationTokenBuilder<TestingAuthenticationTokenConfigurer>
			implements
			AuthenticationConfigurer<TestingAuthenticationToken> {
	}
}
