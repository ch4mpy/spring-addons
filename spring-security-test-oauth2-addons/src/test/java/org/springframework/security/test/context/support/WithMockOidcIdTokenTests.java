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
package org.springframework.security.test.context.support;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.test.configuration.Defaults;
import org.springframework.security.test.support.openid.OAuth2LoginAuthenticationTokenTestingBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class WithMockOidcIdTokenTests {

	@Test
	public void defaults() {
		final WithMockOidcIdToken auth = AnnotationUtils.findAnnotation(Annotated.class, WithMockOidcIdToken.class);
		assertThat(auth.accessTokenValue()).isEqualTo(Defaults.BEARER_TOKEN_VALUE);
		assertThat(auth.idTokenValue()).isEqualTo(Defaults.JWT_VALUE);
		assertThat(auth.subject()).isEqualTo(Defaults.SUBJECT);
		assertThat(auth.nameAttributeKey()).isEqualTo(OAuth2LoginAuthenticationTokenTestingBuilder.DEFAULT_NAME_ATTRIBUTE_KEY);
		assertThat(auth.name()).isEqualTo(Defaults.AUTH_NAME);

		final WithSecurityContext context =
				AnnotatedElementUtils.findMergedAnnotation(Annotated.class, WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_METHOD);
	}

	@WithMockOidcIdToken
	private static class Annotated {
	}

	@Test
	public void findMergedAnnotationWhenSetupExplicitThenOverridden() {
		final WithSecurityContext context =
				AnnotatedElementUtils.findMergedAnnotation(SetupExplicit.class, WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_METHOD);
	}

	@WithMockOidcIdToken(setupBefore = TestExecutionEvent.TEST_METHOD)
	private class SetupExplicit {
	}

	@Test
	public void findMergedAnnotationWhenSetupOverriddenThenOverridden() {
		final WithSecurityContext context =
				AnnotatedElementUtils.findMergedAnnotation(SetupOverridden.class, WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_EXECUTION);
	}

	@WithMockOidcIdToken(setupBefore = TestExecutionEvent.TEST_EXECUTION)
	private class SetupOverridden {
	}
}
