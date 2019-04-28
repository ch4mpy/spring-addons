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
package org.springframework.security.test.web.servlet.request;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.accessToken;

import java.util.Collection;
import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.test.support.OAuth2IntrospectionAuthenticationTokenBuilder;
import org.springframework.security.test.support.missingpublicapi.OAuth2IntrospectionClaimNames;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class AccessTokenRequestPostProcessorTests extends AbstractRequestPostProcessorTests {
	private OAuth2IntrospectionAuthenticationTokenBuilder builder;

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		builder = new OAuth2IntrospectionAuthenticationTokenBuilder()
				.attribute(OAuth2IntrospectionClaimNames.USERNAME, TEST_NAME)
				.attribute("scope", Collections.singleton("test:claim"));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void test() {
		final OAuth2IntrospectionAuthenticationToken actual =
				(OAuth2IntrospectionAuthenticationToken) authentication(accessToken(builder).postProcessRequest(request));

		assertThat(actual.getName()).isEqualTo(TEST_NAME);
		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(new SimpleGrantedAuthority("SCOPE_test:claim"));
		assertThat((Collection<String>) actual.getTokenAttributes().get(OAuth2IntrospectionClaimNames.SCOPE)).containsExactlyInAnyOrder("test:claim");
		assertThat((Collection<String>) actual.getToken().getScopes()).containsExactlyInAnyOrder("test:claim");
	}

}
