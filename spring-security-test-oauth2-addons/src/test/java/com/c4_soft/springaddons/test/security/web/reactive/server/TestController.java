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
package com.c4_soft.springaddons.test.security.web.reactive.server;

import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.oauth2.rfc7519.JwtClaimSet;
import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RestController
public class TestController {
	@GetMapping("/authentication")
	public String jwt(Authentication authentication) {
		final var authorities = authentication.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());

		return String.format(
				"Authenticated as %s granted with %s. Authentication type is %s.",
				authentication.getName(),
				authorities.toString(),
				authentication.getClass().getName(),
				authentication.getPrincipal().getClass().getName());
	}

	@GetMapping("/jwt")
	public String accessToken(JwtAuthenticationToken authentication) {
		return String.format(
				"You are successfully authenticated and granted with %s claims using a JSON Web Token.",
				((Jwt) authentication.getPrincipal()).getClaims());
	}

	@GetMapping("/jwt-claims")
	public String jwtClaimSet(OAuth2ClaimSetAuthentication<JwtClaimSet> authentication) {
		return String.format(
				"You are successfully authenticated and granted with %s claims using a JSON Web Token.",
				authentication.getClaimSet());
	}

	@GetMapping("/introspection")
	public String accessToken(OAuth2IntrospectionAuthenticationToken authentication) {
		return String.format(
				"You are successfully authenticated and granted with %s claims using a bearer token and OAuth2 introspection endpoint.",
				authentication.getPrincipal());
	}

	@GetMapping("/introspection-claims")
	public String introspectionClaimSet(OAuth2ClaimSetAuthentication<IntrospectionClaimSet> authentication) {
		return String.format(
				"You are successfully authenticated and granted with %s claims using a bearer token and OAuth2 introspection endpoint.",
				authentication.getClaimSet());
	}
}
