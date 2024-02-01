package com.c4_soft.springaddons.security.oidc.starter;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.oauth2.jwt.JwtClaimNames;

import com.c4_soft.springaddons.security.oidc.starter.properties.SimpleAuthoritiesMappingProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ByIssuerAuthoritiesMappingPropertiesResolver implements AuthoritiesMappingPropertiesResolver {
    private final SpringAddonsOidcProperties properties;

    @Override
    public List<SimpleAuthoritiesMappingProperties> resolve(Map<String, Object> claimSet) {
        final var iss = Optional.ofNullable(claimSet.get(JwtClaimNames.ISS)).orElse(null);
        return properties.getOpProperties(iss).getAuthorities();
    }
}
