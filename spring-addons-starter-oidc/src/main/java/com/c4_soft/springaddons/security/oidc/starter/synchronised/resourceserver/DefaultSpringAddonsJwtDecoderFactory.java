package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.client.RestOperations;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsJwtValidators;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;

/**
 * <p>
 * Provides with a JwtDecoder (configured with the required validators). Both JWK-set and issuer
 * URIs are optional, but at least one must be provided.
 * </p>
 * <p>
 * Uses {@link OpenidProviderPropertiesResolver} to resolve the matching OpenID Provider
 * configuration properties and throws an exception if none are found (the token issuer is not
 * trusted).
 * </p>
 * <p>
 * The validators are those of {@link SpringAddonsJwtValidators#createDefault(Optional, Optional, List,
 * org.springframework.security.oauth2.core.OAuth2TokenValidator...)}.
 * </p>
 */
public class DefaultSpringAddonsJwtDecoderFactory implements SpringAddonsJwtDecoderFactory {

  private final Optional<RestOperations> rest;

  public DefaultSpringAddonsJwtDecoderFactory(RestOperations rest) {
    this.rest = Optional.ofNullable(rest);
  }

  public DefaultSpringAddonsJwtDecoderFactory() {
    this.rest = Optional.empty();
  }

  /**
   * Same as {@link #create(Optional, Optional, Optional, List)} with
   * {@link OpenidProviderProperties#DEFAULT_TYP}, like the auto-configuration when the {@code typ}
   * property is not set: unlike earlier versions, {@code at+jwt} tokens are accepted. Final: the
   * auto-configured resolvers would never call an override, and a subclass overriding it fails to
   * compile, or to load when compiled against an earlier version.
   *
   * @deprecated call {@link #create(Optional, Optional, Optional, List)} with the accepted
   *             {@code typ} values: {@link OpenidProviderProperties#DEFAULT_TYP}, or
   *             {@code List.of("jwt")} for the behavior of versions before 9.5.3
   */
  @Deprecated(since = "9.5.3", forRemoval = true)
  public final JwtDecoder create(Optional<URI> jwkSetUri, Optional<URI> issuer,
      Optional<String> audience) {
    return create(jwkSetUri, issuer, audience, OpenidProviderProperties.DEFAULT_TYP);
  }

  /**
   * @return a {@link NimbusJwtDecoder}, so that an override can call {@code super} and set other
   *         validators with {@link SpringAddonsJwtValidators#createDefault(Optional, Optional, List,
   *         org.springframework.security.oauth2.core.OAuth2TokenValidator...)}
   */
  @Override
  public NimbusJwtDecoder create(Optional<URI> jwkSetUri, Optional<URI> issuer,
      Optional<String> audience, List<String> typ) {

    final var decoderBuilder =
        jwkSetUri.isPresent() ? NimbusJwtDecoder.withJwkSetUri(jwkSetUri.get().toString())
            : NimbusJwtDecoder.withIssuerLocation(issuer
                .orElseThrow(() -> new InvalidJwtDecoderCreationParametersException()).toString());

    rest.ifPresent(decoderBuilder::restOperations);

    final var decoder = decoderBuilder.build();
    decoder.setJwtValidator(SpringAddonsJwtValidators.createDefault(issuer, audience, typ));

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
