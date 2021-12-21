package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4_soft.springaddons.security.oauth2.ReactiveJwt2GrantedAuthoritiesConverter;
import com.nimbusds.jose.shaded.json.JSONArray;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Flux;

@RequiredArgsConstructor
public class Auth0ReactiveJwt2GrantedAuthoritiesConverter implements ReactiveJwt2GrantedAuthoritiesConverter {

	private final SecurityProperties securityProperties;

	@Override
	public Flux<GrantedAuthority> convert(Jwt jwt) {
		final JSONArray roles = Optional.ofNullable((JSONArray) jwt.getClaims().get(securityProperties.getAuth0().getRolesClaim())).orElse(new JSONArray());

		return Flux.fromStream(roles.stream().map(Object::toString).map(SimpleGrantedAuthority::new));
	}

}