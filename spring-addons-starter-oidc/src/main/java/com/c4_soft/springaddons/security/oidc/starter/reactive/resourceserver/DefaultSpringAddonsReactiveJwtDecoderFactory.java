package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ResponseStatus;

import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Provides with a JwtDecoder (configured with the required validators). Both JWK-set and issuer URIs are optional, but at least one must be provided.
 * </p>
 * <p>
 * Uses {@link OpenidProviderPropertiesResolver} to resolve the matching OpenID Provider configuration properties and throws an exception if none are found (the
 * token issuer is not trusted).
 * </p>
 */
@RequiredArgsConstructor
public class DefaultSpringAddonsReactiveJwtDecoderFactory implements SpringAddonsReactiveJwtDecoderFactory {

    @Override
    public ReactiveJwtDecoder create(Optional<URI> jwkSetUri, Optional<URI> issuer, Optional<String> audience) {

        final var decoder = jwkSetUri.isPresent()
            ? NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri.get().toString()).build()
            : NimbusReactiveJwtDecoder
                .withIssuerLocation(issuer.orElseThrow(() -> new InvalidReactiveJwtDecoderCreationParametersException()).toString())
                .build();

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
    static class InvalidReactiveJwtDecoderCreationParametersException extends RuntimeException {
        private static final long serialVersionUID = 3575615882241560832L;

        public InvalidReactiveJwtDecoderCreationParametersException() {
            super("At least one of jwkSetUri or issuer must be provided");
        }
    }
}
