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

import static com.c4soft.springaddons.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.jwtOauth2Authentication;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.c4soft.oauth2.rfc7519.JwtClaimSet;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4soft.springaddons.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.JwtOAuth2AuthenticationRequestPostProcessor;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class JwtOAuth2AuthenticationRequestPostProcessorTests extends AbstractRequestPostProcessorTests {
	final JwtOAuth2AuthenticationRequestPostProcessor authConfigurer = jwtOauth2Authentication(claims -> claims
					.subject(TEST_NAME)
					.authorities("test:claim"));

	@SuppressWarnings("unchecked")
	@Test
	public void test() {
		final OAuth2ClaimSetAuthentication<JwtClaimSet> actual =
				(OAuth2ClaimSetAuthentication<JwtClaimSet>) getSecurityContextAuthentication(authConfigurer.postProcessRequest(request));

		assertThat(actual.getName()).isEqualTo(TEST_NAME);
		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(new SimpleGrantedAuthority("test:claim"));
		assertThat(actual.getClaimSet().getSubject()).isEqualTo(TEST_NAME);
	}

}
