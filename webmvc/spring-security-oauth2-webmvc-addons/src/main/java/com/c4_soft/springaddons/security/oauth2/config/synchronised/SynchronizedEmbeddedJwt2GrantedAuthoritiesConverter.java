package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.Collection;
import java.util.Objects;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2GrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.MissingAuthorizationServerConfigurationException;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class SynchronizedEmbeddedJwt2GrantedAuthoritiesConverter implements SynchronizedJwt2GrantedAuthoritiesConverter {
	private final SpringAddonsSecurityProperties securityProperties;

	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		return Stream
				.of(securityProperties.getAuthorities())
				.filter(ap -> Objects.equals(ap.getAuthorizationServerLocation(), jwt.getIssuer().toString()))
				.findAny()
				.map(ap -> ap.mapAuthorities(jwt.getClaims()).toList())
				.orElseThrow(() -> new MissingAuthorizationServerConfigurationException(jwt.getIssuer()));
	}

}