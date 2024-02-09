package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import java.net.URI;
import java.util.Optional;

import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;

/**
 * <p>
 * Provides with a JwtDecoder (configured with the required validators). Both JWK-set and issuer URIs are optional, but at least one should be provided.
 * </p>
 * <p>
 * {@link DefaultSpringAddonsReactiveJwtDecoderFactory}, the default implementation uses {@link OpenidProviderPropertiesResolver} to resolve the matching OpenID Provider
 * configuration properties and throws an exception if none are found (the token issuer is not trusted).
 * </p>
 */
public interface SpringAddonsReactiveJwtDecoderFactory {
    ReactiveJwtDecoder create(Optional<URI> jwkSetUri, Optional<URI> issuer, Optional<String> audience);
}
