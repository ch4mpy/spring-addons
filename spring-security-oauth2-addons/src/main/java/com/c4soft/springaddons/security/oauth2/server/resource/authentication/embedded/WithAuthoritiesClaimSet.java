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

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.c4soft.oauth2.ClaimSet;

/**
 * {@link ClaimSet} extension to use when authorities are embedded in the token claims
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public interface WithAuthoritiesClaimSet extends ClaimSet {

	default Set<String> getAuthorities() {
		final Set<String> claim =  getAsStringSet(ClaimGrantedAuthoritiesService.AUTHORITIES_CLAIM_NAME);
		return claim == null ? Collections.emptySet() : claim;
	}

	static interface Builder<T extends Builder<T>> {

		default T authorities(Stream<String> authorities) {
			return claim(ClaimGrantedAuthoritiesService.AUTHORITIES_CLAIM_NAME, authorities.collect(Collectors.toSet()));
		}

		default T authorities(String... authorities) {
			return authorities(Stream.of(authorities));
		}

		default T authorities(Collection<String> authorities) {
			return authorities(authorities.stream());
		}

		T claim(String name, Object value);

	}
}
