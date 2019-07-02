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
package com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded;

import java.security.Principal;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Retrieves authorities from the token "authorities" claim
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class AuthoritiesClaim2GrantedAuthoritySetConverter<T extends WithAuthoritiesClaimSet & Principal> implements Converter<T, Set<GrantedAuthority>> {

	@Override
	public Set<GrantedAuthority> convert(T claimSet) {
		return claimSet.getAuthorities().stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

}
