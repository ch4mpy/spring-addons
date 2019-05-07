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
package org.springframework.security.test.web.reactive.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.OAuth2SecurityMockServerConfigurers.mockAuthentication;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.test.support.openid.OAuth2LoginAuthenticationTokenTestingBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OidcIdTokenMutatorTests {
	private OAuth2LoginAuthenticationTokenTestingBuilder<?> builder;

	@Before
	public void setUp() {
		builder = new OAuth2LoginAuthenticationTokenTestingBuilder<>(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

// @formatter:off
	@Test
	public void testDefaultOidcIdTokenConfigurer() {
		TestController.clientBuilder().apply(mockAuthentication(builder)).build()
				.get().uri("/greet").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("Hello, user!");

		final String actual = TestController.clientBuilder()
				.apply(mockAuthentication(builder)).build()
				.get().uri("/authorities").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).returnResult().getResponseBody();
		assertThat(actual).contains("SCOPE_USER");
		assertThat(actual).contains("SCOPE_openid");
	}

	@Test
	public void testCustomOidcIdTokenConfigurer() {
		builder.name("ch4mpy").scope("message:read");

		TestController.clientBuilder()
				.apply(mockAuthentication(builder)).build()
				.get().uri("/greet").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("Hello, ch4mpy!");

		String actual = TestController.clientBuilder()
				.apply(mockAuthentication(builder)).build()
				.get().uri("/authorities").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).returnResult().getResponseBody();
		assertThat(actual).contains("SCOPE_message:read");
		assertThat(actual).contains("SCOPE_openid");

		actual = TestController.client()
				.mutateWith(mockAuthentication(builder))
				.get().uri("/open-id").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).returnResult().getResponseBody();
		assertThat(actual).contains("Hello, ch4mpy!");
		assertThat(actual).contains("SCOPE_message:read");
		assertThat(actual).contains("SCOPE_openid");
		assertThat(actual).contains("OidcId token");
	}

	@Test
	public void testCustomOidcIdTokenMutator() {
		builder.name("ch4mpy").scope("message:read");

		TestController.client()
				.mutateWith((mockAuthentication(builder)))
				.get().uri("/greet").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("Hello, ch4mpy!");

		String actual = TestController.client()
				.mutateWith((mockAuthentication(builder)))
				.get().uri("/authorities").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).returnResult().getResponseBody();
		assertThat(actual).contains("SCOPE_message:read");
		assertThat(actual).contains("SCOPE_openid");

		actual = TestController.client()
				.mutateWith(mockAuthentication(builder))
				.get().uri("/open-id").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).returnResult().getResponseBody();
		assertThat(actual).contains("Hello, ch4mpy!");
		assertThat(actual).contains("SCOPE_message:read");
		assertThat(actual).contains("SCOPE_openid");
		assertThat(actual).contains("OidcId token");
	}
// @formatter:on
}
