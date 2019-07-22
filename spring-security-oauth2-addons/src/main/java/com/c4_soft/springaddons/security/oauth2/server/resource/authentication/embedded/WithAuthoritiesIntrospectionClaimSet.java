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

import java.util.Map;

import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;

/**
 * Introspection claim-set with embedded authorities
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class WithAuthoritiesIntrospectionClaimSet extends IntrospectionClaimSet implements WithAuthoritiesClaimSet {

	private final String authoritiesClaimName;

	public WithAuthoritiesIntrospectionClaimSet(Map<String, Object> claims, String authoritiesClaimName) {
		super(claims);
		this.authoritiesClaimName = authoritiesClaimName;
	}

	@Override
	public String authoritiesClaimName() {
		return authoritiesClaimName;
	}

	public static Builder<?> builder() {
		return new Builder<>();
	}

	public static Builder<?> builder(String authoritiesClaimName) {
		final var builder = new Builder<>();
		builder.authoritiesClaimName(authoritiesClaimName);
		return builder;
	}

	public static class Builder<T extends Builder<T>> extends IntrospectionClaimSet.Builder<T> implements WithAuthoritiesClaimSet.Builder<T> {
		private static final long serialVersionUID = 3668529199860842750L;

		private String authoritiesClaimName = WithAuthoritiesClaimSet.DEFAULT_AUTHORITIES_CLAIM_NAME;

		public T authoritiesClaimName(String authoritiesClaimName) {
			this.authoritiesClaimName = authoritiesClaimName;
			return downcast();
		}

		@Override
		public T claim(String name, Object value) {
			super.claim(name, value);
			return downcast();
		};

		@Override
		public WithAuthoritiesIntrospectionClaimSet build() {
			return build(this);
		}

		@Override
		public WithAuthoritiesIntrospectionClaimSet build(Map<String, Object> claims) {
			return new WithAuthoritiesIntrospectionClaimSet(claims, authoritiesClaimName);
		}

	}
}
