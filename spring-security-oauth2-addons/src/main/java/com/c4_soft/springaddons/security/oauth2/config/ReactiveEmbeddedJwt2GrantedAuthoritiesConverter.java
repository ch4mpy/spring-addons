package com.c4_soft.springaddons.security.oauth2.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2GrantedAuthoritiesConverter;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Flux;

@RequiredArgsConstructor
public class ReactiveEmbeddedJwt2GrantedAuthoritiesConverter implements ReactiveJwt2GrantedAuthoritiesConverter {
	private final SpringAddonsSecurityProperties securityProperties;

	@Override
	public Flux<GrantedAuthority> convert(Jwt jwt) {
		return Flux.fromStream(securityProperties.getAuthorities(jwt.getClaims()));
	}

}