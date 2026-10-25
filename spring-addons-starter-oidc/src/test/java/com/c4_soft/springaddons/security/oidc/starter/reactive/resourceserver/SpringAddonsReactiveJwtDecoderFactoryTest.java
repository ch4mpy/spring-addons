package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsJwtValidators;
import com.c4_soft.springaddons.security.oidc.starter.TestJwkSet;

/**
 * The Javadoc snippets of {@link SpringAddonsReactiveJwtDecoderFactory}, run against tokens signed by
 * {@link TestJwkSet}.
 */
class SpringAddonsReactiveJwtDecoderFactoryTest {

  private static final URI ISSUER = URI.create("https://op/realm");
  private static TestJwkSet jwks;

  @BeforeAll
  static void startJwkSetServer() throws Exception {
    jwks = new TestJwkSet();
  }

  @AfterAll
  static void stopJwkSetServer() {
    jwks.close();
  }

  /** The migration snippet of the interface Javadoc: a lambda written before typ existed. */
  static SpringAddonsReactiveJwtDecoderFactory migratedLambdaFactory() {
    // was: (jwkSetUri, issuer, audience) -> ...
    return (jwkSetUri, issuer, audience, typ) -> myReactiveJwtDecoder(jwkSetUri, issuer,
        audience);
  }

  static ReactiveJwtDecoder myReactiveJwtDecoder(Optional<URI> jwkSetUri, Optional<URI> issuer,
      Optional<String> audience) {
    return NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri.orElseThrow().toString()).build();
  }

  @Test
  void givenMigratedLambda_whenTypIsAtJwt_thenTypPropertyIsIgnored() throws Exception {
    final ReactiveJwtDecoder decoder = migratedLambdaFactory().create(Optional.of(jwks.jwkSetUri()),
        Optional.of(ISSUER), Optional.of("bff"), List.of("at+jwt"));

    // the lambda's own decoder applies Spring Security defaults: JWT only, whatever typ says
    assertThat(decoder.decode(token("JWT")).block().getSubject()).isEqualTo("ch4mp");
    assertThatThrownBy(() -> decoder.decode(token("at+jwt")).block()).isInstanceOf(BadJwtException.class);
  }

  /** The "typ aware" snippet of the interface Javadoc, verbatim. */
  static SpringAddonsReactiveJwtDecoderFactory springAddonsJwtDecoderFactory() {
    return (jwkSetUri, issuer, audience, typ) -> {
      final var decoder = jwkSetUri
          .map(uri -> NimbusReactiveJwtDecoder.withJwkSetUri(uri.toString()))
          .orElseGet(() -> NimbusReactiveJwtDecoder.withIssuerLocation(issuer.orElseThrow().toString()))
          // the Spring Security 6.5 Nimbus processor accepts only typ JWT (or none) by default
          .jwtProcessorCustomizer(processor -> processor
              .setJWSTypeVerifier(SpringAddonsJwtValidators.joseTypeVerifier(typ)))
          .build();
      decoder.setJwtValidator(SpringAddonsJwtValidators.createDefault(issuer, audience, typ));
      return decoder;
    };
  }

  @Test
  void givenTypAwareSnippetAndTypIsAtJwt_whenDecode_thenOnlyAtJwtIsAccepted() throws Exception {
    final ReactiveJwtDecoder decoder = springAddonsJwtDecoderFactory().create(
        Optional.of(jwks.jwkSetUri()), Optional.of(ISSUER), Optional.of("bff"), List.of("at+jwt"));

    assertThat(decoder.decode(token("at+jwt")).block().getSubject()).isEqualTo("ch4mp");
    assertThat(decoder.decode(token("application/at+jwt")).block().getSubject()).isEqualTo("ch4mp");
    assertThatThrownBy(() -> decoder.decode(token("JWT")).block()).isInstanceOf(BadJwtException.class)
        .hasStackTraceContaining("typ");
    assertThatThrownBy(() -> decoder.decode(token(null)).block()).isInstanceOf(BadJwtException.class)
        .hasStackTraceContaining("typ");
  }

  @Test
  void givenTypAwareSnippet_whenIssuerOrAudienceDoesNotMatch_thenRejected() throws Exception {
    final ReactiveJwtDecoder decoder = springAddonsJwtDecoderFactory().create(
        Optional.of(jwks.jwkSetUri()), Optional.of(ISSUER), Optional.of("bff"), List.of("at+jwt"));

    assertThatThrownBy(() -> decoder
        .decode(jwks.sign("at+jwt", TestJwkSet.claims("https://attacker", "bff"))).block())
            .isInstanceOf(BadJwtException.class);
    assertThatThrownBy(() -> decoder
        .decode(jwks.sign("at+jwt", TestJwkSet.claims(ISSUER.toString(), "other"))).block())
            .isInstanceOf(BadJwtException.class);
  }

  private static String token(String typ) throws Exception {
    return jwks.sign(typ, TestJwkSet.claims(ISSUER.toString(), "bff"));
  }
}
