/*
 * Copyright 2019 Jérôme Wacongne.
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
package com.c4_soft.springaddons.test.security.context.support;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
public class WithMockKeycloackAuthTests {

	private WithMockKeycloackAuth.Factory factory;

	@Before
	public void setUp() {
		factory = new WithMockKeycloackAuth.Factory();
	}

	@Test
	public void testDefaultValuesAreSet() {
		final var annotation = AnnotationUtils.findAnnotation(Default.class, WithMockKeycloackAuth.class);
		final var actual = factory.authentication(annotation);

		assertThat(actual.getName()).isEqualTo("user");
		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("ROLE_offline_access"),
				new SimpleGrantedAuthority("ROLE_uma_authorization"));
	}

	@Test
	public void testAuthoritiesActualyOverridesDefaultAuthorities() {
		final var annotation = AnnotationUtils.findAnnotation(Authorities.class, WithMockKeycloackAuth.class);
		final var actual = factory.authentication(annotation);

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("ROLE_TESTER"),
				new SimpleGrantedAuthority("ROLE_AUTHOR"));
	}

	@Test
	public void testNameActualyOverridesDefaultName() {
		final var annotation = AnnotationUtils.findAnnotation(Name.class, WithMockKeycloackAuth.class);
		final var actual = factory.authentication(annotation);

		assertThat(actual.getName()).isEqualTo("ch4mpy");
	}

	@WithMockKeycloackAuth
	private static class Default {
	}

	@WithMockKeycloackAuth({ "TESTER", "AUTHOR" })
	private static class Authorities {
	}

	@WithMockKeycloackAuth(name = "ch4mpy")
	private static class Name {
	}
}
