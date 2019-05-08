package org.springframework.security.test.support;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class TestingAuthenticationTokenBuilder<T extends TestingAuthenticationTokenBuilder<T>> implements AuthenticationBuilder<TestingAuthenticationToken> {
	private String name;
	private Object principal;
	private Object credentials;
	private final Set<GrantedAuthority> authorities;

	public TestingAuthenticationTokenBuilder() {
		super();
		this.name = Defaults.AUTH_NAME;
		this.authorities = new HashSet<>(Set.of(new SimpleGrantedAuthority("ROLE_USER")));
	}

	public T name(String name) {
		this.name = name;
		return downcast();
	}

	public T principal(Object principal) {
		this.principal = principal;
		return downcast();
	}

	public T credentials(Object credentials) {
		this.credentials = credentials;
		return downcast();
	}

	public T authorities(Collection<GrantedAuthority> authorities) {
		this.authorities.clear();
		this.authorities.addAll(authorities);
		return downcast();
	}

	public T authorities(String... authorities) {
		return authorities(asGrantedAuthorities(authorities));
	}

	public T authority(GrantedAuthority authority) {
		this.authorities.add(authority);
		return downcast();
	}

	public T authority(String authority) {
		this.authorities.add(new SimpleGrantedAuthority(authority));
		return downcast();
	}

	@Override
	public TestingAuthenticationToken build() {
		return new TestingAuthenticationToken(principal == null ? name : principal, credentials, new ArrayList<>(authorities));
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}

	private static Collection<GrantedAuthority> asGrantedAuthorities(Stream<String> authorities) {
		return authorities.map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
	}

	private static Collection<GrantedAuthority> asGrantedAuthorities(String... authorities) {
		return asGrantedAuthorities(Stream.of(authorities));
	}
}