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

public class SimpleTestingAuthenticationTokenBuilder implements AuthenticationBuilder<TestingAuthenticationToken> {
	private String name;
	private final Set<GrantedAuthority> authorities;

	public SimpleTestingAuthenticationTokenBuilder() {
		super();
		this.name = Defaults.AUTH_NAME;
		this.authorities = new HashSet<>(Set.of(new SimpleGrantedAuthority("ROLE_USER")));
	}

	public SimpleTestingAuthenticationTokenBuilder name(String name) {
		this.name = name;
		return this;
	}

	public SimpleTestingAuthenticationTokenBuilder authorities(Collection<GrantedAuthority> authorities) {
		this.authorities.clear();
		this.authorities.addAll(authorities);
		return this;
	}

	public SimpleTestingAuthenticationTokenBuilder authorities(String... authorities) {
		return authorities(asGrantedAuthorities(authorities));
	}

	public SimpleTestingAuthenticationTokenBuilder authority(GrantedAuthority authority) {
		this.authorities.add(authority);
		return this;
	}

	public SimpleTestingAuthenticationTokenBuilder authority(String authority) {
		this.authorities.add(new SimpleGrantedAuthority(authority));
		return this;
	}

	@Override
	public TestingAuthenticationToken build() {
		return new TestingAuthenticationToken(name, null, new ArrayList<>(authorities));
	}

	private static Collection<GrantedAuthority> asGrantedAuthorities(Stream<String> authorities) {
		return authorities.map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
	}

	private static Collection<GrantedAuthority> asGrantedAuthorities(String... authorities) {
		return asGrantedAuthorities(Stream.of(authorities));
	}
}