package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.c4_soft.springaddons.security.oauth2.AuthenticationBuilder;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdBuilder;
import com.c4_soft.springaddons.security.oauth2.test.Defaults;

public class OidcIdAuthenticationTokenTestingBuilder<T extends OidcIdAuthenticationTokenTestingBuilder<T>>
		implements
		AuthenticationBuilder<OidcIdAuthenticationToken> {

	protected final OidcIdBuilder tokenBuilder;
	private final Set<String> authorities;

	public OidcIdAuthenticationTokenTestingBuilder() {
		super();
		this.tokenBuilder = new OidcIdBuilder().name(Defaults.AUTH_NAME);
		this.authorities = new HashSet<>(Arrays.asList(Defaults.AUTHORITIES));
	}

	@Override
	public OidcIdAuthenticationToken build() {
		return new OidcIdAuthenticationToken(
				tokenBuilder.build(),
				authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));
	}

	public T authorities(String... authorities) {
		this.authorities.clear();
		this.authorities.addAll(Arrays.asList(authorities));
		return downcast();
	}

	public T token(Consumer<OidcIdBuilder> tokenBuilderConsumer) {
		tokenBuilderConsumer.accept(tokenBuilder);
		return downcast();
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}
}