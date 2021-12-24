package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2GrantedAuthoritiesConverter;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class KeycloakSynchronizedJwt2GrantedAuthoritiesConverter implements SynchronizedJwt2GrantedAuthoritiesConverter {
	private final SpringAddonsSecurityProperties securityProperties;

	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		final JSONArray realmRoles =
				Optional
						.ofNullable((JSONObject) jwt.getClaims().get("realm_access"))
						.flatMap(realmAccess -> Optional.ofNullable((JSONArray) realmAccess.get("roles")))
						.orElse(new JSONArray());

		final JSONArray clientRoles =
				Optional
						.ofNullable((JSONObject) jwt.getClaims().get("resource_access"))
						.flatMap(resourceAccess -> Optional.ofNullable((JSONObject) resourceAccess.get(securityProperties.getKeycloak().getClientId())))
						.flatMap(clientResourceAccess -> Optional.ofNullable((JSONArray) clientResourceAccess.get("roles")))
						.orElse(new JSONArray());

		return Stream
				.concat(realmRoles.stream(), clientRoles.stream())
				.map(Object::toString)
				.map(r -> securityProperties.getAuthoritiesPrefix() + (securityProperties.isUppercaseAuthorities() ? r.toUpperCase() : r))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

}