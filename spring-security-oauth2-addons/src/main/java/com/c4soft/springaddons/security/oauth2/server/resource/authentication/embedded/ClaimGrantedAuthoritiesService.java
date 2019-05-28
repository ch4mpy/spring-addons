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
package com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded;

import java.security.Principal;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

import com.c4soft.oauth2.ClaimSet;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2Authentication;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.PrincipalGrantedAuthoritiesService;

/**
 * Retrieves authorities from the {@link OAuth2Authentication#getPrincipal()} itself (token claim-set must contain an {@value #AUTHORITIES_CLAIM_NAME} claim)
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class ClaimGrantedAuthoritiesService implements PrincipalGrantedAuthoritiesService {
	public static final String AUTHORITIES_CLAIM_NAME = "authorities";

	@Override
	public Collection<GrantedAuthority> getAuthorities(Principal principal) {
		Assert.isTrue(
				principal instanceof ClaimSet,
				"principal must be an instance of TokenProperties (was " + principal == null ? "null" : principal.getClass().getName() + ")");

		final ClaimSet claims = (ClaimSet) principal;
		final Set<String> authoritiesClaim = claims.getAsStringSet(AUTHORITIES_CLAIM_NAME);

		Assert.notNull(authoritiesClaim, "principal has no \"" + AUTHORITIES_CLAIM_NAME + "\" claim");

		return authoritiesClaim.stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

}
