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

import static org.assertj.core.api.Assertions.assertThat;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Ch4mp
 *
 */
public class ScopePrefixAuthoritiesClaim2GrantedAuthoritySetConverterTests {

	ScopePrefixAuthoritiesClaim2GrantedAuthoritySetConverter<TestWithAuthoritiesClaimSet> conv =
			new ScopePrefixAuthoritiesClaim2GrantedAuthoritySetConverter<>(":");

	@Test
	public void testConvertFiltersOnScopesAndRemovesPrefix() {
		TestWithAuthoritiesClaimSet claimSet = new TestWithAuthoritiesClaimSet(Map.of(
				"authorities", List.of("test:a1", "other:a2", "ingnored:a3"),
				"scope", "test other"));

		final var actual = conv.convert(claimSet);
		assertThat(actual).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("a1"),
				new SimpleGrantedAuthority("a2"));
	}

	private static class TestWithAuthoritiesClaimSet extends HashMap<String, Object> implements WithAuthoritiesClaimSet, Principal {
		private static final long serialVersionUID = -8570028159688993456L;

		public TestWithAuthoritiesClaimSet(Map<? extends String, ? extends Object> m) {
			super(m);
		}

		@Override
		public String getName() {
			return null;
		}
	}
}
