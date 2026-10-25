package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsJwtValidators;

/**
 * <p>
 * Provides with a JwtDecoder (configured with the required validators). Both JWK-set and issuer URIs are optional, but at least one should be provided.
 * </p>
 * <p>
 * {@link DefaultSpringAddonsReactiveJwtDecoderFactory}, the default implementation uses {@link OpenidProviderPropertiesResolver} to resolve the matching OpenID Provider
 * configuration properties and throws an exception if none are found (the token issuer is not trusted).
 * </p>
 * <p>
 * Before 9.5.3, {@code create} had no {@code typ} parameter. A factory written then as a lambda gets the new parameter and can keep ignoring it, in which case
 * the {@code typ} property of the OpenID Provider has no effect for it:
 * </p>
 *
 * <pre>
 * &#64;Bean
 * SpringAddonsReactiveJwtDecoderFactory springAddonsJwtDecoderFactory() {
 *     // was: (jwkSetUri, issuer, audience) -&gt; ...
 *     return (jwkSetUri, issuer, audience, typ) -&gt; myReactiveJwtDecoder(jwkSetUri, issuer, audience);
 * }
 * </pre>
 * <p>
 * A {@code NimbusReactiveJwtDecoder} applying the {@code typ} of the OpenID Provider, along with the other default validators (timestamps, X.509 thumbprint, issuer and
 * audience):
 * </p>
 *
 * <pre>
 * &#64;Bean
 * SpringAddonsReactiveJwtDecoderFactory springAddonsJwtDecoderFactory() {
 *     return (jwkSetUri, issuer, audience, typ) -&gt; {
 *         final var decoder = jwkSetUri
 *             .map(uri -&gt; NimbusReactiveJwtDecoder.withJwkSetUri(uri.toString()))
 *             .orElseGet(() -&gt; NimbusReactiveJwtDecoder.withIssuerLocation(issuer.orElseThrow().toString()))
 *             .build();
 *         decoder.setJwtValidator(SpringAddonsJwtValidators.createDefault(issuer, audience, typ));
 *         return decoder;
 *     };
 * }
 * </pre>
 * <p>
 * {@link DefaultSpringAddonsReactiveJwtDecoderFactory} builds the same decoder, and answers {@code 401} when neither URI is configured. A subclass can override its {@code create}, call {@code super} and set other validators.
 * </p>
 */
@FunctionalInterface
public interface SpringAddonsReactiveJwtDecoderFactory {

    /**
     * @param jwkSetUri the JWK set URI of the OpenID Provider, if configured
     * @param issuer the issuer URI, if configured
     * @param audience the audience, if configured
     * @param typ the accepted values for the {@code typ} JOSE header, see {@link SpringAddonsJwtValidators#typValidator(List)}. The auto-configured resolvers
     *        pass {@link SpringAddonsJwtValidators#effectiveTyp(List)}: never null nor empty
     * @return a JWT decoder for tokens of this OpenID Provider
     */
    ReactiveJwtDecoder create(Optional<URI> jwkSetUri, Optional<URI> issuer, Optional<String> audience, List<String> typ);
}
