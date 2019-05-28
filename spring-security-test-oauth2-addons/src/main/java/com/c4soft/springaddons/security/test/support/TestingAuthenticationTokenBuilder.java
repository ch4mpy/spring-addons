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
package com.c4soft.springaddons.security.test.support;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Convenient builder for {@link  TestingAuthenticationToken} which defaults name and authorities with expected values
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 * @param <T> capture for extending class type
 */
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