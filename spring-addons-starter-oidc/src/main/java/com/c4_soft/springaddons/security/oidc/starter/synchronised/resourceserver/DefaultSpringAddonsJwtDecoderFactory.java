package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ResponseStatus;

import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Provides with a JwtDecoder (configured with the required validators). Both JWK-set and issuer URIs are optional, but at least one must be provided.
 * </p>
 * <p>
 * Uses {@link OpenidProviderPropertiesResolver} to resolve the matching OpenID Provider configuration properties and throws an exception if none are found
 * (the token issuer is not trusted).
 * </p>
 */
@RequiredArgsConstructor
public class DefaultSpringAddonsJwtDecoderFactory implements SpringAddonsJwtDecoderFactory {

    @Override
    public JwtDecoder create(Optional<URI> jwkSetUri, Optional<URI> issuer, Optional<String> audience) {

        final var decoder = jwkSetUri.isPresent()
            ? NimbusJwtDecoder.withJwkSetUri(jwkSetUri.get().toString()).build()
            : NimbusJwtDecoder.withIssuerLocation(issuer.orElseThrow(() -> new InvalidJwtDecoderCreationParametersException()).toString()).build();

        final OAuth2TokenValidator<Jwt> defaultValidator = issuer
            .map(URI::toString)
            .map(JwtValidators::createDefaultWithIssuer)
            .orElse(JwtValidators.createDefault());

        // @formatter:off
		final OAuth2TokenValidator<Jwt> jwtValidator = audience
				.filter(StringUtils::hasText)
				.map(opAudience -> new JwtClaimValidator<List<String>>(
						JwtClaimNames.AUD,
						(aud) -> aud != null && aud.contains(opAudience)))
				.map(audValidator -> (OAuth2TokenValidator<Jwt>) new DelegatingOAuth2TokenValidator<>(List.of(defaultValidator, audValidator)))
				.orElse(defaultValidator);
		// @formatter:on

        decoder.setJwtValidator(jwtValidator);

        return decoder;
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    static class InvalidJwtDecoderCreationParametersException extends RuntimeException {
        private static final long serialVersionUID = 3575615882241560832L;

        public InvalidJwtDecoderCreationParametersException() {
            super("At least one of jwkSetUri or issuer must be provided");
        }
    }
}