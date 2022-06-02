package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.AuthoritiesMappingProperties;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class SimpleJwtGrantedAuthoritiesConverter implements JwtGrantedAuthoritiesConverter {
	private final SpringAddonsSecurityProperties properties;

	@Override
	public Collection<? extends GrantedAuthority> convert(Jwt source) {
		final var issuerAuthorityMappingProperties = getIssuerAuthorityMappingProperties(source);
		return Stream
				.of(issuerAuthorityMappingProperties.getClaims())
				.flatMap(rolesPath -> getRoles(source.getClaims(), rolesPath))
				.map(r -> issuerAuthorityMappingProperties.getPrefix() + (issuerAuthorityMappingProperties.isToUpperCase() ? r.toUpperCase() : r))
				.map(r -> (GrantedAuthority) new SimpleGrantedAuthority(r))
				.toList();
	}

	private final AuthoritiesMappingProperties getIssuerAuthorityMappingProperties(Jwt jwt) {
		return Stream
				.of(properties.getAuthorities())
				.filter(ap -> Objects.equals(ap.getAuthorizationServerLocation(), jwt.getIssuer().toString()))
				.findAny()
				.orElseThrow(() -> new MissingAuthorizationServerConfigurationException(jwt.getIssuer()));
	}

	private static Stream<String> getRoles(Map<String, Object> claims, String rolesPath) {
		final var claimsToWalk = rolesPath.split("\\.");
		var i = 0;
		var obj = Optional.of(claims);
		while (i++ < claimsToWalk.length) {
			final var claimName = claimsToWalk[i - 1];
			if (i == claimsToWalk.length) {
				return obj.map(o -> (JSONArray) o.get(claimName)).orElse(new JSONArray()).stream().map(Object::toString);
			}
			obj = obj.map(o -> (JSONObject) o.get(claimName));

		}
		return Stream.empty();
	}

}
