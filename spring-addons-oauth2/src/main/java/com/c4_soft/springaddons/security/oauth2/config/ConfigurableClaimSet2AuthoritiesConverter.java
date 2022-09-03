package com.c4_soft.springaddons.security.oauth2.config;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.Case;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.SimpleAuthoritiesMappingProperties;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ConfigurableClaimSet2AuthoritiesConverter implements OAuth2AuthoritiesConverter {
	private final SpringAddonsSecurityProperties properties;

	@Override
	public Collection<? extends GrantedAuthority> convert(Map<String, Object> source) {
		final var authoritiesMappingProperties = getAuthoritiesMappingProperties(source);
		return Stream.of(authoritiesMappingProperties.getClaims()).flatMap(rolesPath -> getRoles(source, rolesPath))
				.map(r -> String.format("%s%s", authoritiesMappingProperties.getPrefix(), processCase(r, authoritiesMappingProperties.getCaze())))
				.map(r -> (GrantedAuthority) new SimpleGrantedAuthority(r)).toList();
	}

	private String processCase(String role, Case caze) {
		switch (caze) {
		case UPPER: {
			return role.toUpperCase();
		}
		case LOWER: {
			return role.toLowerCase();
		}
		default:
			return role;
		}
	}

	private SimpleAuthoritiesMappingProperties getAuthoritiesMappingProperties(Map<String, Object> claimSet) {
		return Stream.of(properties.getIssuers()).filter(ap -> Objects.equals(ap.getLocation().toString(), claimSet.get(JwtClaimNames.ISS).toString()))
				.findAny()
				.orElseThrow(
						() -> new MissingAuthorizationServerConfigurationException(
								Optional.ofNullable(claimSet.get(JwtClaimNames.ISS)).map(Object::toString).orElse(null)))
				.getAuthorities();
	}

	@SuppressWarnings("unchecked")
	private static Stream<String> getRoles(Map<String, Object> claims, String rolesPath) {
		final var claimsToWalk = rolesPath.split("\\.");
		var i = 0;
		var obj = Optional.of(claims);
		while (i++ < claimsToWalk.length) {
			final var claimName = claimsToWalk[i - 1];
			if (i == claimsToWalk.length) {
				return obj.map(o -> (List<Object>) o.get(claimName)).orElse(List.of()).stream().map(Object::toString);
			}
			obj = obj.map(o -> (Map<String, Object>) o.get(claimName));

		}
		return Stream.empty();
	}

}
