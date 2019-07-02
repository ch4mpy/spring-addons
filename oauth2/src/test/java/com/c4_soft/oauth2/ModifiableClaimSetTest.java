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
package com.c4_soft.oauth2;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import com.c4_soft.oauth2.ModifiableClaimSet;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class ModifiableClaimSetTest {

	@Test
	public void putActuallyPutsValue() {
		final var props = new ModifiableClaimSet();
		props.put("name1", "value");
		assertThat(props.get("name1")).isEqualTo("value");

	}

	@Test
	public void putOverwritesExisingValue() {
		final var props = new ModifiableClaimSet(Map.of("name1", "value1"));
		props.claim("name1", "overriden");
		assertThat(props.get("name1")).isEqualTo("overriden");
	}

	@Test
	public void putEmptyStringRemovesValue() {
		final var props = new ModifiableClaimSet(Map.of("name1", "value1"));
		props.claim("name1", "");
		assertThat(props.containsKey("name1")).isFalse();
	}

	@Test
	public void putNullStringRemovesValue() {
		final var props = new ModifiableClaimSet(Map.of("name1", "value1"));
		props.claim("name1", (String) null);
		assertThat(props.containsKey("name1")).isFalse();
	}

	@Test
	public void putOrRemoveNonEmptyCollectionActuallyPutsValue() {
		final var props = new ModifiableClaimSet(Map.of("name1", "value1"));
		props.claim("name1", Set.of("overriden"));
		assertThat(props.get("name1")).isEqualTo(Set.of("overriden"));
	}

	@Test
	public void putOrRemoveEmptyCollectionRemovesValue() {
		final var props = new ModifiableClaimSet(Map.of("name1", "value1"));
		props.claim("name1", Collections.emptySet());
		assertThat(props.containsKey("name1")).isFalse();
	}

	@Test
	public void putOrRemoveNullCollectionRemovesValue() {
		final var props = new ModifiableClaimSet(Map.of("name1", "value1"));
		props.claim("name1", (Collection<?>) null);
		assertThat(props.containsKey("name1")).isFalse();
	}

	@Test
	public void putOrRemoveNullObjectRemovesValue() {
		final var props = new ModifiableClaimSet(Map.of("name1", "value1"));
		props.claim("name1", (Object) null);
		assertThat(props.containsKey("name1")).isFalse();
	}
}
