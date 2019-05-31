/*
 * Copyright 2019 Jérôme Wacongne.
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

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import java.security.Principal;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4soft.oauth2.rfc7519.JwtClaimSet;
import com.c4soft.oauth2.rfc7662.IntrospectionClaimSet;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RestController
public class TestController {

	@GetMapping("/greet")
	public String greet(Principal authentication) {
		return String.format("Hello, %s!", authentication.getName());
	}

	@GetMapping("/authorities")
	public String authentication(Authentication authentication) {
		return authentication.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList())
				.toString();
	}

	@GetMapping("/jwt")
	public String jwt(Authentication authentication) {
		final Jwt token = (Jwt) authentication.getPrincipal();
		final String scopes = (String) token.getClaims().get("scope");

		return String.format(
				"Hello, %s! You are successfully authenticated and granted with [%s] scopes using a JSON Web Token.",
				token.getSubject(),
				scopes);
	}

	@GetMapping("/jwt-claims")
	public String jwtClaimSet(OAuth2ClaimSetAuthentication<JwtClaimSet> authentication) {
		final JwtClaimSet claims = authentication.getClaimSet();

		return String.format(
				"Hello, %s! You are successfully authenticated and granted with %s claims using a JSON Web Token.",
				authentication.getName(),
				claims);
	}

	@GetMapping("/introspection")
	public String accessToken(Authentication authentication) {
		@SuppressWarnings("unchecked")
		final Map<String, Object> tokenAttributes = (Map<String, Object>) authentication.getPrincipal();
		return String.format(
				"Hello, %s! You are successfully authenticated and granted with %s scopes using a bearer token and OAuth2 introspection endpoint.",
				tokenAttributes.get("username"),
				tokenAttributes.get("scope").toString());
	}

	@GetMapping("/introspection-claims")
	public String introspectionClaimSet(OAuth2ClaimSetAuthentication<IntrospectionClaimSet> authentication) {
		final IntrospectionClaimSet claims = authentication.getClaimSet();

		return String.format(
				"Hello, %s! You are successfully authenticated and granted with %s claims using a bearer token and OAuth2 introspection endpoint.",
				authentication.getName(),
				claims);
	}

	public static WebTestClient.Builder clientBuilder() {
		return WebTestClient.bindToController(new TestController())
				.webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
				.apply(springSecurity())
				.configureClient()
				.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
	}

	public static WebTestClient client() {
		return clientBuilder().build();
	}
}
