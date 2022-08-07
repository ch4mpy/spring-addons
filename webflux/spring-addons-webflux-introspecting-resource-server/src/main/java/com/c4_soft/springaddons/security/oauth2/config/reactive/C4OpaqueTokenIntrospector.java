package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.io.Serializable;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.config.ClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.TokenAttributes2ClaimSetConverter;

import reactor.core.publisher.Mono;

public class C4OpaqueTokenIntrospector<T extends Map<String, Object> & Serializable> implements ReactiveOpaqueTokenIntrospector {
	private final NimbusOpaqueTokenIntrospector delegate;
	private final TokenAttributes2ClaimSetConverter<T> claimsConverter;
	private final ClaimSet2AuthoritiesConverter<T> authoritiesConverter;

	public C4OpaqueTokenIntrospector(
			String introspectionUri,
			String clientId,
			String clientSecret,
			TokenAttributes2ClaimSetConverter<T> claimsConverter,
			ClaimSet2AuthoritiesConverter<T> authoritiesConverter) {
		this.delegate = new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
		this.claimsConverter = claimsConverter;
		this.authoritiesConverter = authoritiesConverter;
	}

	@Override
	public Mono<OAuth2AuthenticatedPrincipal> introspect(String token) {
		final var auth = this.delegate.introspect(token);
		final var claims = claimsConverter.convert(auth.getAttributes());
		return Mono.just(new OAuthentication<>(claims, authoritiesConverter.convert(claims), token));
	}

}