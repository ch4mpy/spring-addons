/*
 * Copyright 2019 Jérôme Wacongne
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
package com.c4_soft.springaddons.security.oauth2.test.webflux.webtestclient;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.c4_soft.springaddons.security.oauth2.test.Defaults;

public class MockAuthenticationWebTestClientConfigurer<T extends Authentication>
		implements
		AuthenticationConfigurer<T> {

	private final T authMock;

	private MockAuthenticationWebTestClientConfigurer(T authMock) {
		this.authMock = authMock;
	}

	@Override
	public T build() {
		return authMock;
	}

	public MockAuthenticationWebTestClientConfigurer<T> authorities(String... authorities) {
		return authorities(Stream.of(authorities));
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public MockAuthenticationWebTestClientConfigurer<T> authorities(Stream<String> authorities) {
		when(authMock.getAuthorities())
				.thenReturn((Collection) authorities.map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));
		return this;
	}

	public MockAuthenticationWebTestClientConfigurer<T> name(String name) {
		when(authMock.getName()).thenReturn(name);
		return this;
	}

	public MockAuthenticationWebTestClientConfigurer<T> credentials(Object credentials) {
		when(authMock.getCredentials()).thenReturn(credentials);
		return this;
	}

	public MockAuthenticationWebTestClientConfigurer<T> details(Object details) {
		when(authMock.getDetails()).thenReturn(details);
		return this;
	}

	public MockAuthenticationWebTestClientConfigurer<T> principal(Object principal) {
		when(authMock.getPrincipal()).thenReturn(principal);
		return this;
	}

	public MockAuthenticationWebTestClientConfigurer<T> setAuthenticated(boolean authenticated) {
		when(authMock.isAuthenticated()).thenReturn(authenticated);
		return this;
	}

	public static MockAuthenticationWebTestClientConfigurer<Authentication> mockAuthentication() {
		return mockAuthentication(Authentication.class);
	}

	public static <T extends Authentication> MockAuthenticationWebTestClientConfigurer<T>
			mockAuthentication(Class<T> authType) {
		return mockAuthentication(authType, auth -> {});
	}

	public static <T extends Authentication> MockAuthenticationWebTestClientConfigurer<T>
			mockAuthentication(Class<T> authType, Consumer<T> authMockConfigurer) {
		final var authMock = authMock(authType);
		authMockConfigurer.accept(authMock);
		return new MockAuthenticationWebTestClientConfigurer<>(authMock);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	static <T extends Authentication> T authMock(Class<T> authType) {
		final var auth = mock(authType);
		when(auth.getAuthorities()).thenReturn((Collection) Defaults.GRANTED_AUTHORITIES);
		when(auth.getName()).thenReturn(Defaults.AUTH_NAME);
		when(auth.isAuthenticated()).thenReturn(true);
		return auth;
	}

}
