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
package com.c4soft.springaddons.sample.authorization.web;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.c4soft.oauth2.rfc7662.IntrospectionClaimNames;

/**
 * Legacy Authorization Server (spring-security-oauth2) does not support any
 * Token Introspection endpoint.
 *
 * This class adds ad-hoc support in order to better support the other samples
 * in the repo.
 */
@FrameworkEndpoint
@RequestMapping("/introspect")
@Profile("!jwt")
class IntrospectEndpoint {
	final TokenStore tokenStore;
	final boolean authoritiesClaim;

	public IntrospectEndpoint(TokenStore tokenStore, Environment env) {
		this.tokenStore = tokenStore;
		this.authoritiesClaim = Stream.of(env.getActiveProfiles()).anyMatch("authorities-claim"::equals);
	}

	@CrossOrigin(origins = "https://localhost:8090")
	@PostMapping
	@ResponseBody
	public Map<String, Object> introspect(@RequestParam("token") String token) {
		final OAuth2AccessToken accessToken = tokenStore.readAccessToken(token);

		if (accessToken == null || accessToken.isExpired()) {
			return Map.of(IntrospectionClaimNames.ACTIVE.value, false);
		}

		final OAuth2Authentication authentication = tokenStore.readAuthentication(token);

		final Map<String, Object> attributes = new HashMap<>(accessToken.getAdditionalInformation());

		attributes.put(IntrospectionClaimNames.SUBJECT.value, authentication.getName());

		final Set<String> scopes = accessToken.getScope();
		attributes.put(IntrospectionClaimNames.SCOPE.value, scopes.stream().collect(Collectors.joining(" ")));

		if (authoritiesClaim && authentication.getAuthorities().size() > 0) {
			attributes.put("authorities", authentication.getAuthorities().stream()
					.map(GrantedAuthority::getAuthority)
					.filter(a -> scopes.contains(a.split(":")[0]))
					.collect(Collectors.toSet()));
		}

		attributes.put(IntrospectionClaimNames.ACTIVE.value, true);

		return attributes;
	}
}