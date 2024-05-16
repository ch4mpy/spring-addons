package com.c4_soft.springaddons.security.oidc.starter;

import java.util.Map;
import java.util.Optional;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;

/**
 * Resolves OpenID Provider configuration properties from OAuth2 / OpenID claims (decoded from a JWT, introspected from an opaque token or
 * retrieved from userinfo endpoint)
 */
public interface OpenidProviderPropertiesResolver {
	Optional<OpenidProviderProperties> resolve(Map<String, Object> claimSet);
}
