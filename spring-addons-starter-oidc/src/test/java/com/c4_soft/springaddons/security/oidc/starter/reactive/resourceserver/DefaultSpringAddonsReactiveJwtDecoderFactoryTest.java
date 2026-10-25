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
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import com.c4_soft.springaddons.security.oidc.starter.TestJwkSet;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;

/**
 * Tokens are signed with a key whose JWK set is served by {@link TestJwkSet}, so that what is
 * tested is the real {@code NimbusReactiveJwtDecoder} built by the factory.
 */
class DefaultSpringAddonsReactiveJwtDecoderFactoryTest {

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

  @Test
  void givenTypIsJwt_whenTypIsJwtOrAbsent_thenDecoded() throws Exception {
    final var decoder = decoder(List.of("JWT"));

    assertThat(decoder.decode(token("JWT")).block().getSubject()).isEqualTo("ch4mp");
    assertThat(decoder.decode(token(null)).block().getSubject()).isEqualTo("ch4mp");
  }

  @Test
  void givenTypIsJwt_whenTypIsAtJwt_thenRejected() throws Exception {
    final var decoder = decoder(List.of("JWT"));

    assertThatThrownBy(() -> decoder.decode(token("at+jwt")).block())
        .isInstanceOf(BadJwtException.class).hasStackTraceContaining("not allowed");
  }

  @Test
  void givenTypIsAtJwt_whenTypIsAtJwt_thenDecoded() throws Exception {
    final var decoder = decoder(List.of("at+jwt"));

    assertThat(decoder.decode(token("at+jwt")).block().getSubject()).isEqualTo("ch4mp");
  }

  @Test
  void givenTypIsAtJwt_whenTypIsJwtOrAbsent_thenRejected() throws Exception {
    final var decoder = decoder(List.of("at+jwt"));

    assertThatThrownBy(() -> decoder.decode(token("JWT")).block())
        .isInstanceOf(BadJwtException.class).hasStackTraceContaining("not allowed");
    assertThatThrownBy(() -> decoder.decode(token(null)).block())
        .isInstanceOf(BadJwtException.class).hasStackTraceContaining("not allowed");
  }

  @Test
  void givenTypIsJwtAndAtJwt_whenTypIsAnyOfThemOrAbsent_thenDecoded() throws Exception {
    final var decoder = decoder(List.of("jwt", "at+jwt"));

    assertThat(decoder.decode(token("JWT")).block().getSubject()).isEqualTo("ch4mp");
    assertThat(decoder.decode(token("at+jwt")).block().getSubject()).isEqualTo("ch4mp");
    assertThat(decoder.decode(token(null)).block().getSubject()).isEqualTo("ch4mp");
    assertThatThrownBy(() -> decoder.decode(token("secevent+jwt")).block())
        .isInstanceOf(BadJwtException.class).hasStackTraceContaining("not allowed");
  }

  @Test
  void givenTypIsAtJwt_whenIssuerOrAudienceDoesNotMatch_thenRejected() throws Exception {
    final var decoder = decoder(List.of("at+jwt"));

    assertThatThrownBy(() -> decoder
        .decode(jwks.sign("at+jwt", TestJwkSet.claims("https://attacker", "bff"))).block())
            .isInstanceOf(JwtValidationException.class);
    assertThatThrownBy(() -> decoder
        .decode(jwks.sign("at+jwt", TestJwkSet.claims(ISSUER.toString(), "other"))).block())
            .isInstanceOf(JwtValidationException.class);
  }

  @Test
  void givenDefaultTyp_whenDecode_thenJwtAtJwtAndNoTypAreDecoded() throws Exception {
    final var decoder = decoder(OpenidProviderProperties.DEFAULT_TYP);

    assertThat(decoder.decode(token("JWT")).block().getSubject()).isEqualTo("ch4mp");
    assertThat(decoder.decode(token("at+jwt")).block().getSubject()).isEqualTo("ch4mp");
    assertThat(decoder.decode(token(null)).block().getSubject()).isEqualTo("ch4mp");
    assertThat(decoder.decode(token("application/at+jwt")).block().getSubject()).isEqualTo("ch4mp");
    assertThat(decoder.decode(token("")).block().getSubject()).isEqualTo("ch4mp");
    assertThatThrownBy(() -> decoder.decode(token("secevent+jwt")).block())
        .isInstanceOf(BadJwtException.class).hasStackTraceContaining("not allowed");
  }

  @Test
  @SuppressWarnings("removal")
  void givenDeprecatedThreeArgumentsCreate_whenDecode_thenDefaultTypApplies() throws Exception {
    final var decoder = new DefaultSpringAddonsReactiveJwtDecoderFactory()
        .create(Optional.of(jwks.jwkSetUri()), Optional.of(ISSUER), Optional.of("bff"));

    assertThat(decoder.decode(token("JWT")).block().getSubject()).isEqualTo("ch4mp");
    assertThat(decoder.decode(token("at+jwt")).block().getSubject()).isEqualTo("ch4mp");
    assertThat(decoder.decode(token(null)).block().getSubject()).isEqualTo("ch4mp");
    assertThatThrownBy(() -> decoder.decode(token("secevent+jwt")).block())
        .isInstanceOf(BadJwtException.class).hasStackTraceContaining("not allowed");
  }

  @Test
  void givenNeitherJwkSetUriNorIssuer_whenCreate_thenThrows() {
    assertThatThrownBy(() -> new DefaultSpringAddonsReactiveJwtDecoderFactory()
        .create(Optional.empty(), Optional.empty(), Optional.empty(), List.of("JWT")))
            .isInstanceOf(
                DefaultSpringAddonsReactiveJwtDecoderFactory.InvalidReactiveJwtDecoderCreationParametersException.class);
  }

  @Test
  void givenValidatorReplacedWithSpringDefaults_whenTypIsNotAccepted_thenStillRejected()
      throws Exception {
    final var decoder = new DefaultSpringAddonsReactiveJwtDecoderFactory().create(
        Optional.of(jwks.jwkSetUri()), Optional.of(ISSUER), Optional.of("bff"), List.of("at+jwt"));
    // Spring Security 6.5 default validators have no typ check: the Nimbus processor keeps it
    decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(ISSUER.toString()));

    assertThat(decoder.decode(token("at+jwt")).block().getSubject()).isEqualTo("ch4mp");
    assertThatThrownBy(() -> decoder.decode(token("secevent+jwt")).block())
        .isInstanceOf(BadJwtException.class).hasStackTraceContaining("not allowed");
    assertThatThrownBy(() -> decoder.decode(token(null)).block())
        .isInstanceOf(BadJwtException.class).hasStackTraceContaining("not allowed");
  }

  private static ReactiveJwtDecoder decoder(List<String> typ) {
    return new DefaultSpringAddonsReactiveJwtDecoderFactory().create(
        Optional.of(jwks.jwkSetUri()), Optional.of(ISSUER), Optional.of("bff"), typ);
  }

  private static String token(String typ) throws Exception {
    return jwks.sign(typ, TestJwkSet.claims(ISSUER.toString(), "bff"));
  }
}
