package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.util.Objects;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.MissingAuthorizationServerConfigurationException;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Flux;

@RequiredArgsConstructor
public class ReactiveEmbeddedJwt2GrantedAuthoritiesConverter implements ReactiveJwt2GrantedAuthoritiesConverter {
	private final SpringAddonsSecurityProperties securityProperties;

	@Override
	public Flux<GrantedAuthority> convert(Jwt jwt) {
		return Flux
				.fromStream(
						Stream
								.of(securityProperties.getAuthorities())
								.filter(ap -> Objects.equals(ap.getAuthorizationServerLocation(), jwt.getIssuer().toString()))
								.findAny()
								.map(ap -> ap.mapAuthorities(jwt.getClaims()))
								.orElseThrow(() -> new MissingAuthorizationServerConfigurationException(jwt.getIssuer())));
	}

}