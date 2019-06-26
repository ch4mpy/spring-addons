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
package com.c4soft.springaddons.sample.resource.jpa;

import java.security.Principal;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.transaction.annotation.Transactional;

import com.c4soft.oauth2.ClaimSet;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class ScopePrefixedJpaGrantedAuthoritiesConverter<T extends ClaimSet & Principal> extends JpaGrantedAuthoritiesConverter<T> {

	private final String sep;

	public ScopePrefixedJpaGrantedAuthoritiesConverter(UserAuthorityRepository authoritiesRepo, String sep) {
		super(authoritiesRepo);
		this.sep = sep;
	}

	@Autowired
	public ScopePrefixedJpaGrantedAuthoritiesConverter(UserAuthorityRepository authoritiesRepo) {
		this(authoritiesRepo, ":");
	}

	@Override
	@Transactional(readOnly = true)
	public Set<GrantedAuthority> convert(T claimSet) {
		final Set<GrantedAuthority> authorities = super.convert(claimSet);
		final Set<String> scopes = claimSet.getAsStringSet(claimSet.containsKey("scope") ? "scope" : "scp");
		return authorities.stream()
				.map(GrantedAuthority::getAuthority)
				.filter(authority -> scopes == null ? true : scopes.contains(authority.split(sep)[0]))
				.map(authority -> Stream.of(authority.split(sep)).skip(1).collect(Collectors.joining(sep)))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

}
