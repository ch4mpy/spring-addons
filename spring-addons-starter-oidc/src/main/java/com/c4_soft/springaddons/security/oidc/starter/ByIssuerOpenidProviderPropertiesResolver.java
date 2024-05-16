package com.c4_soft.springaddons.security.oidc.starter;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.springframework.security.oauth2.jwt.JwtClaimNames;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ByIssuerOpenidProviderPropertiesResolver implements OpenidProviderPropertiesResolver {
	private final SpringAddonsOidcProperties properties;

	@Override
	public Optional<OpenidProviderProperties> resolve(Map<String, Object> claimSet) {
		final var iss = Optional.ofNullable(claimSet.get(JwtClaimNames.ISS)).map(Object::toString).orElse(null);
		return properties
				.getOps()
				.stream()
				.filter(issuerProps -> Objects.equals(Optional.ofNullable(issuerProps.getIss()).map(URI::toString).orElse(null), iss))
				.findAny();
	}
}
