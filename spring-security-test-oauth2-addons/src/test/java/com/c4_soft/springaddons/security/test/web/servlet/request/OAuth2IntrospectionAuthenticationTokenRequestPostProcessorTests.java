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
package com.c4_soft.springaddons.security.test.web.servlet.request;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;

import com.c4_soft.springaddons.security.test.support.introspection.OAuth2IntrospectionAuthenticationTokenUnitTestsParent;
import com.c4_soft.springaddons.security.test.support.missingpublicapi.SecurityContextRequestPostProcessorSupport.TestSecurityContextRepository;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2IntrospectionAuthenticationTokenRequestPostProcessorTests
		extends
		OAuth2IntrospectionAuthenticationTokenUnitTestsParent {

	static Authentication getSecurityContextAuthentication(MockHttpServletRequest req) {
		return TestSecurityContextRepository.getContext(req).getAuthentication();
	}

	@Test
	public void test() {
		final OAuth2IntrospectionAuthenticationToken actual =
				(OAuth2IntrospectionAuthenticationToken) getSecurityContextAuthentication(
						securityRequestPostProcessor().name("ch4mpy")
								.authorities("TEST_AUTHORITY")
								.postProcessRequest(new MockHttpServletRequest()));

		assertThat(actual.getName()).isEqualTo("ch4mpy");
		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(new SimpleGrantedAuthority("TEST_AUTHORITY"));
	}

}
