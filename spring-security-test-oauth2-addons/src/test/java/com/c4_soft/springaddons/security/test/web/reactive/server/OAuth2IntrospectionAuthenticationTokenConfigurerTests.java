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
package com.c4_soft.springaddons.security.test.web.reactive.server;

import static com.c4_soft.springaddons.security.test.web.reactive.server.OAuth2SecurityMockServerConfigurers.mockIntrospectedToken;

import org.junit.Test;

import com.c4_soft.springaddons.security.test.web.reactive.server.OAuth2SecurityMockServerConfigurers.OAuth2IntrospectionAuthenticationTokenConfigurer;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2IntrospectionAuthenticationTokenConfigurerTests {
// @formatter:off

	@Test
	public void testDefaultAccessTokenConfigurerSetNameToUser() {
		TestController.clientBuilder()
				.apply(mockIntrospectedToken()).build()
				.get().uri("/greet").exchange()
				.expectBody(String.class).isEqualTo("Hello, user!");
	}

	@Test
	public void testDefaultAccessTokenConfigurerSetScopesToUser() {
		TestController.clientBuilder()
				.apply(mockIntrospectedToken()).build()
				.get().uri("/authorities").exchange()
				.expectBody(String.class).isEqualTo("[SCOPE_USER]");
	}

	@Test
	public void testCustomAccessTokenConfigurer() {
		final OAuth2IntrospectionAuthenticationTokenConfigurer authConfigurer = mockIntrospectedToken()
				.token(accessToken -> accessToken.attributes(claims -> claims
						.username("ch4mpy")
						.scope("message:read")));

		TestController.clientBuilder()
				.apply(authConfigurer).build()
				.get().uri("/greet").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("Hello, ch4mpy!");

		TestController.clientBuilder()
				.apply(authConfigurer).build()
				.get().uri("/authorities").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("[SCOPE_message:read]");

		TestController.clientBuilder()
				.apply(authConfigurer).build()
				.get().uri("/introspection").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(
						"Hello, ch4mpy! You are successfully authenticated and granted with [message:read] scopes using a bearer token and OAuth2 introspection endpoint.");

	}

	@Test
	public void testCustomAccessTokenMutator() {
		final OAuth2IntrospectionAuthenticationTokenConfigurer authConfigurer = mockIntrospectedToken()
				.token(accessToken -> accessToken.attributes(claims -> claims
						.username("ch4mpy")
						.scope("message:read")));

		TestController.client()
				.mutateWith(authConfigurer)
				.get().uri("/greet").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("Hello, ch4mpy!");

		TestController.client()
				.mutateWith(authConfigurer)
				.get().uri("/authorities").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("[SCOPE_message:read]");

		TestController.client()
				.mutateWith(authConfigurer)
				.get().uri("/introspection").exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(
						"Hello, ch4mpy! You are successfully authenticated and granted with [message:read] scopes using a bearer token and OAuth2 introspection endpoint.");
	}
//@formatter:on
}
