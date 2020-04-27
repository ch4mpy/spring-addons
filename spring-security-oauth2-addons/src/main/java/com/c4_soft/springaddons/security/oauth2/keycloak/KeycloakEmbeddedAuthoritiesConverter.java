package com.c4_soft.springaddons.security.oauth2.keycloak;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

public class KeycloakEmbeddedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		final var realmAccess = (JSONObject) jwt.getClaims().get("realm_access");
		final var roles = (JSONArray) realmAccess.get("roles");
		return roles.stream()
				.map(Object::toString)
				.map(role -> new SimpleGrantedAuthority("ROLE_" + role))
				.collect(Collectors.toSet());
	}

}
