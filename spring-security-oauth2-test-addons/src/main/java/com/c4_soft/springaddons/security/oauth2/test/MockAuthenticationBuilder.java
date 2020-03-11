package com.c4_soft.springaddons.security.oauth2.test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class MockAuthenticationBuilder<T extends Authentication> {

	private final T authMock;

	public MockAuthenticationBuilder(Class<T> authType) {
		this.authMock = mock(authType);
		name(Defaults.AUTH_NAME);
		authorities(Defaults.AUTHORITIES);
		setAuthenticated(true);
	}

	public T build() {
		return authMock;
	}

	public MockAuthenticationBuilder<T> authorities(String... authorities) {
		return authorities(Stream.of(authorities));
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public MockAuthenticationBuilder<T> authorities(Stream<String> authorities) {
		when(authMock.getAuthorities())
				.thenReturn((Collection) authorities.map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));
		return this;
	}

	public MockAuthenticationBuilder<T> name(String name) {
		when(authMock.getName()).thenReturn(name);
		return this;
	}

	public MockAuthenticationBuilder<T> credentials(Object credentials) {
		when(authMock.getCredentials()).thenReturn(credentials);
		return this;
	}

	public MockAuthenticationBuilder<T> details(Object details) {
		when(authMock.getDetails()).thenReturn(details);
		return this;
	}

	public MockAuthenticationBuilder<T> principal(Object principal) {
		when(authMock.getPrincipal()).thenReturn(principal);
		return this;
	}

	public MockAuthenticationBuilder<T> setAuthenticated(boolean authenticated) {
		when(authMock.isAuthenticated()).thenReturn(authenticated);
		return this;
	}

}
