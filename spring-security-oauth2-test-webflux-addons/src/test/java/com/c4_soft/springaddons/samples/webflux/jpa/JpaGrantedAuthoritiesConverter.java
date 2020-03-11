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
package com.c4_soft.springaddons.samples.webflux.jpa;

import java.security.Principal;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.transaction.annotation.Transactional;

import com.c4_soft.springaddons.security.oauth2.ClaimSet;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class JpaGrantedAuthoritiesConverter<T extends ClaimSet & Principal>
		implements
		Converter<Map<String, Object>, Set<GrantedAuthority>> {

	private final UserAuthorityRepository authoritiesRepo;

	private final Converter<Map<String, Object>, T> claimsExtractor;

	@Autowired
	public JpaGrantedAuthoritiesConverter(
			UserAuthorityRepository authoritiesRepo,
			Converter<Map<String, Object>, T> claimsExtractor) {
		this.authoritiesRepo = authoritiesRepo;
		this.claimsExtractor = claimsExtractor;
	}

	@Override
	@Transactional(readOnly = true)
	public Set<GrantedAuthority> convert(Map<String, Object> claimsMap) {
		final var claims = claimsExtractor.convert(claimsMap);
		final Set<String> scopes = claims.getAsStringSet(claims.containsKey("scope") ? "scope" : "scp");
		if (scopes == null || !scopes.contains("showcase")) {
			return Set.of();
		}

		final Collection<UserAuthority> authorities = authoritiesRepo.findByIdUserSubject(claims.getName());
		return authorities.stream()
				.map(UserAuthority::getAuthority)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

}
