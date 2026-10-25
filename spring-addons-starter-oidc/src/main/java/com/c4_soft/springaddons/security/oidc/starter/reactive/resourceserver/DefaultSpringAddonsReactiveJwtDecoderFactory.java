package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.bind.annotation.ResponseStatus;

import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsJwtValidators;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWKSecurityContext;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Provides with a JwtDecoder (configured with the required validators). Both JWK-set and issuer URIs are optional, but at least one must be provided.
 * </p>
 * <p>
 * Uses {@link OpenidProviderPropertiesResolver} to resolve the matching OpenID Provider configuration properties and throws an exception if none are found (the
 * token issuer is not trusted).
 * </p>
 * <p>
 * The validators are those of
 * {@link SpringAddonsJwtValidators#createDefault(Optional, Optional, List, org.springframework.security.oauth2.core.OAuth2TokenValidator...)}. The {@code typ}
 * header is also checked by the Nimbus processor, before any validator, with {@link SpringAddonsJwtValidators#joseTypeVerifier(List)}: replacing the
 * validator can narrow the accepted {@code typ} values, not widen them.
 * </p>
 */
@RequiredArgsConstructor
public class DefaultSpringAddonsReactiveJwtDecoderFactory implements SpringAddonsReactiveJwtDecoderFactory {

    /**
     * Same as {@link #create(Optional, Optional, Optional, List)} with {@link OpenidProviderProperties#DEFAULT_TYP}, like the auto-configuration when the
     * {@code typ} property is not set: unlike earlier versions, {@code at+jwt} tokens are accepted. Final: the auto-configured resolvers would never call an
     * override, and a subclass overriding it fails to compile, or to load when compiled against an earlier version.
     *
     * @deprecated call {@link #create(Optional, Optional, Optional, List)} with the accepted {@code typ} values: {@link OpenidProviderProperties#DEFAULT_TYP},
     *             or {@code List.of("jwt")} for the behavior of versions before 8.5.1
     */
    @Deprecated(since = "8.5.1", forRemoval = true)
    public final ReactiveJwtDecoder create(Optional<URI> jwkSetUri, Optional<URI> issuer, Optional<String> audience) {
        return create(jwkSetUri, issuer, audience, OpenidProviderProperties.DEFAULT_TYP);
    }

    /**
     * @return a {@link NimbusReactiveJwtDecoder}, so that an override can call {@code super} and set other validators with
     *         {@link SpringAddonsJwtValidators#createDefault(Optional, Optional, List, org.springframework.security.oauth2.core.OAuth2TokenValidator...)}
     */
    @Override
    public NimbusReactiveJwtDecoder create(Optional<URI> jwkSetUri, Optional<URI> issuer, Optional<String> audience, List<String> typ) {

        final var decoderBuilder = jwkSetUri.isPresent()
            ? NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri.get().toString())
            : NimbusReactiveJwtDecoder
                .withIssuerLocation(issuer.orElseThrow(() -> new InvalidReactiveJwtDecoderCreationParametersException()).toString());

        // The Spring Security 6.5 Nimbus processor accepts only typ JWT (or none) by default: check the configured values there, which also keeps
        // typ checked if the validator is replaced
        final JOSEObjectTypeVerifier<JWKSecurityContext> typVerifier = SpringAddonsJwtValidators.joseTypeVerifier(typ);
        final var decoder = decoderBuilder.jwtProcessorCustomizer(processor -> processor.setJWSTypeVerifier(typVerifier)).build();

        decoder.setJwtValidator(SpringAddonsJwtValidators.createDefault(issuer, audience, typ));

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
