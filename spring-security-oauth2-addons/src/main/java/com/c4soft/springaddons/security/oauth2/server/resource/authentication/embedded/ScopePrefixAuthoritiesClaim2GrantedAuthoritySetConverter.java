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

package com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded;

import java.security.Principal;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Ch4mp
 *
 */
public class ScopePrefixAuthoritiesClaim2GrantedAuthoritySetConverter<T extends WithAuthoritiesClaimSet & Principal>
		extends
		AuthoritiesClaim2GrantedAuthoritySetConverter<T> {

	private final String sep;

	public ScopePrefixAuthoritiesClaim2GrantedAuthoritySetConverter(String sep) {
		this.sep = sep;
	}

	public ScopePrefixAuthoritiesClaim2GrantedAuthoritySetConverter() {
		this(":");
	}

	@Override
	public Set<GrantedAuthority> convert(T claimSet) {
		final Set<String> scopes = claimSet.getAsStringSet(claimSet.containsKey("scope") ? "scope" : "scp");
		return claimSet.getAuthorities().stream()
				.filter(authority -> scopes == null ? true : scopes.contains(authority.split(sep)[0]))
				.map(authority -> Stream.of(authority.split(sep)).skip(1).collect(Collectors.joining(sep)))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

}
