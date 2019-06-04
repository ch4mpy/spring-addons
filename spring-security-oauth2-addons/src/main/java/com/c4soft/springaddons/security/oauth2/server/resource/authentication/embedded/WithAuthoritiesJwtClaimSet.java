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

import java.util.Map;

import com.c4soft.oauth2.rfc7519.JwtClaimSet;

/**
 * JWT claim-set with embedded authorities
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class WithAuthoritiesJwtClaimSet extends JwtClaimSet implements WithAuthoritiesClaimSet {

	public WithAuthoritiesJwtClaimSet(Map<String, Object> claims) {
		super(claims);
	}

	public static Builder<?> builder() {
		return new Builder<>();
	}

	public static class Builder<T extends Builder<T>> extends JwtClaimSet.Builder<T> implements WithAuthoritiesClaimSet.Builder<T> {
		private static final long serialVersionUID = -2665224594484030875L;

		@Override
		public WithAuthoritiesJwtClaimSet build() {
			return new WithAuthoritiesJwtClaimSet(this);
		}

		@Override
		public T claim(String name, Object value) {
			super.claim(name, value);
			return downcast();
		};

	}
}
