/*
 * Copyright 2019 Jérôme Wacongne
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
package com.c4_soft.springaddons.sample.authorization.config;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import com.c4_soft.oauth2.rfc7519.JwtRegisteredClaimNames;

class SubjectAttributeUserTokenConverter extends DefaultUserAuthenticationConverter {

	private final boolean authoritiesClaim;

	public SubjectAttributeUserTokenConverter(boolean authoritiesClaim) {
		this.authoritiesClaim = authoritiesClaim;
	}

	@Override
	public Map<String, ?> convertUserAuthentication(Authentication authentication) {
		@SuppressWarnings("unchecked")
		final Map<String, Object> details = (Map<String, Object>) authentication.getDetails();

		final Map<String, Object> authClaims = new LinkedHashMap<>(details);
		authClaims.put(JwtRegisteredClaimNames.SUBJECT.value, authentication.getName());

		final Set<String> scopes = details.containsKey("scope")
				? Stream.of(details.get("scope").toString().split(" ")).collect(Collectors.toSet())
				: Collections.emptySet();

		final var scopedAuthorities = authentication.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.filter(authority -> scopes.contains(authority.split(":")[0]))
				.collect(Collectors.toSet());

		if (authoritiesClaim && scopedAuthorities.size() > 0) {
			authClaims.put("authorities", scopedAuthorities);
		}

		return authClaims;
	}
}