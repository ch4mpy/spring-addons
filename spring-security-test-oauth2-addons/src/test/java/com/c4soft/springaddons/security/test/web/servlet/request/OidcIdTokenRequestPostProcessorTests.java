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
package com.c4soft.springaddons.security.test.web.servlet.request;

import static com.c4soft.springaddons.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.oidcId;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OidcIdTokenRequestPostProcessorTests extends AbstractRequestPostProcessorTests {

	@Test
	public void test() {
		final OAuth2LoginAuthenticationToken actual =
				(OAuth2LoginAuthenticationToken) getSecurityContextAuthentication(oidcId()
						.name(TEST_NAME)
						.scope("test:claim")
						.postProcessRequest(request));

		assertThat(actual.getName()).isEqualTo(TEST_NAME);
		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("SCOPE_test:claim"), new SimpleGrantedAuthority("SCOPE_openid"));
		assertThat(actual.getAccessToken().getScopes()).containsExactlyInAnyOrder("test:claim", "openid");
		assertThat(actual.getPrincipal().getName()).isEqualTo(TEST_NAME);
	}

}
