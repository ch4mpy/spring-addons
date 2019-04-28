/*
 * Copyright 2019 Jérôme Wacongne.
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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class StringCollectionAuthoritiesConverterTest {
	// Intentional dirty inputs to check cleanup
	private static final Set<String> SCOPES = Set.of("s1", "s2");

	@Test
	public void testConstructorWithPrefix() {
		final var converter = new StringCollectionAuthoritiesConverter("test_");
		assertThat(converter.convert(SCOPES)).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("test_s1"),
				new SimpleGrantedAuthority("test_s2"));
	}

	@Test
	public void testConstructorNoPrefix() {
		final var converter = new StringCollectionAuthoritiesConverter();
		assertThat(converter.convert(SCOPES)).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("s1"),
				new SimpleGrantedAuthority("s2"));
	}

}
