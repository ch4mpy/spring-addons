/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.transaction.annotation.Transactional;

import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class PersistedGrantedAuthoritiesRetriever implements OAuth2AuthoritiesConverter {

	private final UserAuthorityRepository authoritiesRepo;

	public PersistedGrantedAuthoritiesRetriever(UserAuthorityRepository authoritiesRepo) {
		this.authoritiesRepo = authoritiesRepo;
	}

	@Override
	@Transactional(readOnly = true)
	public Set<GrantedAuthority> convert(Map<String, Object> claims) {
		final Collection<UserAuthority> authorities = authoritiesRepo.findByIdUserSubject(((String) claims.get(JwtClaimNames.SUB)));

		return authorities.stream().map(UserAuthority::getAuthority).map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
	}

}
