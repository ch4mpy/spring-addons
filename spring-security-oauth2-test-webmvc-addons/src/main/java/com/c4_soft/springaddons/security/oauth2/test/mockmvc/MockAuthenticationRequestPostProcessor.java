/*
 * Copyright 2019 Jérôme Wacongne
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

package com.c4_soft.springaddons.security.oauth2.test.mockmvc;

import org.springframework.security.core.Authentication;

import com.c4_soft.springaddons.security.oauth2.test.MockAuthenticationBuilder;

public class MockAuthenticationRequestPostProcessor<T extends Authentication>
		extends
		MockAuthenticationBuilder<T, MockAuthenticationRequestPostProcessor<T>>
		implements
		AuthenticationRequestPostProcessor<T> {

	public MockAuthenticationRequestPostProcessor(Class<T> authType) {
		super(authType);
	}

	public static <T extends Authentication> MockAuthenticationRequestPostProcessor<T>
			mockAuthentication(Class<T> authType) {
		return new MockAuthenticationRequestPostProcessor<>(authType);
	}

	public static MockAuthenticationRequestPostProcessor<Authentication> mockAuthentication() {
		return mockAuthentication(Authentication.class);
	}
}