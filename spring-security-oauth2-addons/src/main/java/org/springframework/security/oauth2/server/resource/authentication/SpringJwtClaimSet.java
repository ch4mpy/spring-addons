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
package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.c4soft.oauth2.rfc7519.JwtClaimSet;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class SpringJwtClaimSet extends JwtClaimSet {

	public SpringJwtClaimSet(Map<String, Object> claims) {
		super(claims);
	}

	public Set<String> getAuthorities() {
		return getAsStringSet("authorities");
	}

	public static Builder<?> builder() {
		return new Builder<>();
	}

	public static class Builder<T extends Builder<T>> extends JwtClaimSet.Builder<T> {

		public T authorities(Stream<String> authorities) {
			return claim("authorities", authorities.collect(Collectors.toSet()));
		}

		public T authorities(String... authorities) {
			return authorities(Stream.of(authorities));
		}

		public T authorities(Collection<String> authorities) {
			return authorities(authorities.stream());
		}

		@Override
		public SpringJwtClaimSet build() {
			return new SpringJwtClaimSet(claimSet);
		}
	}
}
