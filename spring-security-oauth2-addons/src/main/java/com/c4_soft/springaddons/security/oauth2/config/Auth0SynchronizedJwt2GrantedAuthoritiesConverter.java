package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2GrantedAuthoritiesConverter;
import com.nimbusds.jose.shaded.json.JSONArray;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class Auth0SynchronizedJwt2GrantedAuthoritiesConverter implements SynchronizedJwt2GrantedAuthoritiesConverter {

	private final SecurityProperties securityProperties;

	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		final JSONArray roles = Optional.ofNullable((JSONArray) jwt.getClaims().get(securityProperties.getAuth0().getRolesClaim())).orElse(new JSONArray());

		return roles.stream().map(Object::toString).map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
	}

}