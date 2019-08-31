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
package com.c4_soft.springaddons.test.security.web.reactive.server;

import org.assertj.core.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4_soft.springaddons.test.security.support.Defaults;
import com.c4_soft.springaddons.test.web.reactive.support.WebTestClientSupport;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@RunWith(SpringRunner.class)
public class JwtClaimSetAuthenticationConfigurerTests
		extends
		ReactiveJwtClaimSetAuthenticationUnitTestingSupport {

	public JwtClaimSetAuthenticationConfigurerTests() {
		super(new TestController());
	}

// @formatter:off
	@Test
	public void testDefaultJwtConfigurer() {
		webTestClient().with(authentication()).get("/authentication")
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(String.format(
						"Authenticated as %s granted with %s. Authentication type is %s.",
						Defaults.AUTH_NAME,
						Arrays.asList(Defaults.AUTHORITIES),
						OAuth2ClaimSetAuthentication.class.getName()));

		webTestClient().with(authentication()).get("/jwt-claims")
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(
						"You are successfully authenticated and granted with [sub => user] claims using a JSON Web Token.");
	}

	@Test
	public void testCustomJwtConfigurer() {
		ch4mpy().get("/authentication")
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(String.format(
						"Authenticated as %s granted with %s. Authentication type is %s.",
						"ch4mpy",
						"[message:read]",
						OAuth2ClaimSetAuthentication.class.getName()));

		ch4mpy().get("/jwt-claims")
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo(
						"You are successfully authenticated and granted with [sub => ch4mpy] claims using a JSON Web Token.");
	}
// @formatter:on

	private WebTestClientSupport ch4mpy() {
		return webTestClient().with(authentication().name("ch4mpy").authorities("message:read"));
	}
}
