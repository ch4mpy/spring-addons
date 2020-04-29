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
package com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.jpa;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class PersistedGrantedAuthoritiesRetriever implements Converter<Jwt, Collection<GrantedAuthority>> {

	private final UserAuthorityRepository authoritiesRepo;

	@Autowired
	public PersistedGrantedAuthoritiesRetriever(UserAuthorityRepository authoritiesRepo) {
		this.authoritiesRepo = authoritiesRepo;
	}

	@Override
	@Transactional(readOnly = true)
	public Set<GrantedAuthority> convert(Jwt jwt) {
		final Collection<UserAuthority> authorities = authoritiesRepo.findByIdUserSubject(jwt.getSubject());

		return authorities.stream()
				.map(UserAuthority::getAuthority)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

}
