package com.c4_soft.springaddons.security.oauth2.test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class MockAuthenticationBuilder<A extends Authentication, T extends MockAuthenticationBuilder<A, T>> {

	private final A authMock;

	public MockAuthenticationBuilder(Class<A> authType) {
		this.authMock = mock(authType);
		name(Defaults.AUTH_NAME);
		authorities(Defaults.AUTHORITIES.stream());
		setAuthenticated(true);
		principal(Defaults.AUTH_NAME);
		details(Defaults.AUTH_NAME);
		credentials(Defaults.AUTH_NAME);
	}

	public A build() {
		return authMock;
	}

	public T authorities(String... authorities) {
		return authorities(Stream.of(authorities));
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public T authorities(Stream<String> authorities) {
		when(authMock.getAuthorities()).thenReturn((Collection) authorities.map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));
		return downcast();
	}

	public T name(String name) {
		when(authMock.getName()).thenReturn(name);
		return downcast();
	}

	public T credentials(Object credentials) {
		when(authMock.getCredentials()).thenReturn(credentials);
		return downcast();
	}

	public T details(Object details) {
		when(authMock.getDetails()).thenReturn(details);
		return downcast();
	}

	public T principal(Object principal) {
		when(authMock.getPrincipal()).thenReturn(principal);
		return downcast();
	}

	public T setAuthenticated(boolean authenticated) {
		when(authMock.isAuthenticated()).thenReturn(authenticated);
		return downcast();
	}

	public T configure(Consumer<A> authConsumer) {
		authConsumer.accept(authMock);
		return downcast();
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}

}
