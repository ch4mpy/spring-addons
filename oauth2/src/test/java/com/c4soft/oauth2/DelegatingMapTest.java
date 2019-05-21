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
package com.c4soft.oauth2;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class DelegatingMapTest {

	@Test(expected = UnsupportedOperationException.class)
	public void testAcruallyDelegatesToDelegate() {
		new DelegatingMap<>(Collections.unmodifiableMap(Map.of("k", "v"))).put("k2", "v2");
	}

	@Test
	public void testDelegateIsAffectedByMutations() {
		final var delegate = new HashMap<>();
		final var actual = new DelegatingMap<>(delegate);
		actual.put("k", "v");

		assertThat(delegate.get("k")).isEqualTo("v");
		assertThat(actual.get("k")).isEqualTo("v");
	}

}
