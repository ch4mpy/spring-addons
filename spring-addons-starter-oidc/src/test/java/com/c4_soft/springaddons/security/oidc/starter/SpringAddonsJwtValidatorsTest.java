package com.c4_soft.springaddons.security.oidc.starter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;

class SpringAddonsJwtValidatorsTest {

  private static final URI ISSUER = URI.create("https://op/realm");

  @Test
  void givenDefaultTyp_whenTypIsJwtOrAtJwtInAnyCaseOrAbsent_thenValid() {
    final var validator = SpringAddonsJwtValidators.typValidator(OpenidProviderProperties.DEFAULT_TYP);

    assertThat(validator.validate(jwt("JWT")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("at+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("AT+JWT")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt(null)).hasErrors()).isFalse();
  }

  @Test
  void givenDefaultTyp_whenTypIsAnotherValue_thenInvalid() {
    final var validator = SpringAddonsJwtValidators.typValidator(OpenidProviderProperties.DEFAULT_TYP);

    assertThat(validator.validate(jwt("secevent+jwt")).hasErrors()).isTrue();
  }

  @Test
  void givenTypIsAtJwt_whenTypIsAtJwtInAnyCase_thenValid() {
    final var validator = SpringAddonsJwtValidators.typValidator(List.of("at+jwt"));

    assertThat(validator.validate(jwt("at+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("AT+JWT")).hasErrors()).isFalse();
  }

  @Test
  void givenTypIsAtJwt_whenTypIsJwtOrAbsent_thenInvalid() {
    final var validator = SpringAddonsJwtValidators.typValidator(List.of("at+jwt"));

    assertThat(validator.validate(jwt("JWT")).hasErrors()).isTrue();
    assertThat(validator.validate(jwt(null)).hasErrors()).isTrue();
  }

  @Test
  void givenTypIsJwtAndAtJwt_whenTypIsAnyOfThemOrAbsent_thenValid() {
    final var validator = SpringAddonsJwtValidators.typValidator(List.of("jwt", "at+jwt"));

    assertThat(validator.validate(jwt("JWT")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("at+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt(null)).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("secevent+jwt")).hasErrors()).isTrue();
  }

  @Test
  void givenTypIsNullOrEmptyOrBlank_whenValidate_thenDefaultApplies() {
    for (final var typ : Arrays.<List<String>>asList(null, List.of(), List.of(" "))) {
      final var validator = SpringAddonsJwtValidators.typValidator(typ);

      assertThat(validator.validate(jwt("JWT")).hasErrors()).as("JWT with %s", typ).isFalse();
      assertThat(validator.validate(jwt(null)).hasErrors()).as("no typ with %s", typ).isFalse();
      assertThat(validator.validate(jwt("at+jwt")).hasErrors()).as("at+jwt with %s", typ).isFalse();
      assertThat(validator.validate(jwt("secevent+jwt")).hasErrors()).as("other with %s", typ)
          .isTrue();
    }
  }

  @Test
  void givenBlankEntries_whenValidate_thenIgnored() {
    final var validator = SpringAddonsJwtValidators.typValidator(List.of("", " at+jwt "));

    assertThat(validator.validate(jwt("at+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt(null)).hasErrors()).isTrue();
  }

  @Test
  void givenIssuerAndAudience_whenCreateDefault_thenTypIssuerAudienceAndTimestampsAreValidated() {
    final OAuth2TokenValidator<Jwt> validator = SpringAddonsJwtValidators
        .createDefault(Optional.of(ISSUER), Optional.of("bff"), List.of("at+jwt"));

    assertThat(validator.validate(jwt("at+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("JWT")).hasErrors()).as("typ").isTrue();
    assertThat(validator.validate(jwt("at+jwt", "https://attacker", "bff", false)).hasErrors())
        .as("issuer").isTrue();
    assertThat(validator.validate(jwt("at+jwt", ISSUER.toString(), "other", false)).hasErrors())
        .as("audience").isTrue();
    assertThat(validator.validate(jwt("at+jwt", ISSUER.toString(), "bff", true)).hasErrors())
        .as("expired").isTrue();
  }

  @Test
  void givenNeitherIssuerNorAudience_whenCreateDefault_thenOnlyTypAndTimestampsAreValidated() {
    final OAuth2TokenValidator<Jwt> validator =
        SpringAddonsJwtValidators.createDefault(Optional.empty(), Optional.empty(), null);

    assertThat(validator.validate(jwt("JWT", "https://anyone", "anything", false)).hasErrors())
        .isFalse();
    assertThat(validator.validate(jwt("at+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("secevent+jwt")).hasErrors()).isTrue();
  }

  @Test
  void givenDefaultTyp_whenTypHasApplicationPrefix_thenValid() {
    final var validator = SpringAddonsJwtValidators.typValidator(OpenidProviderProperties.DEFAULT_TYP);

    assertThat(validator.validate(jwt("application/at+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("application/jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("Application/AT+JWT")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("application/secevent+jwt")).hasErrors()).isTrue();
  }

  @Test
  void givenTypIsAtJwt_whenTypIsApplicationAtJwt_thenValid() {
    final var validator = SpringAddonsJwtValidators.typValidator(List.of("at+jwt"));

    assertThat(validator.validate(jwt("application/at+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("application/jwt")).hasErrors()).isTrue();
  }

  @Test
  void givenTypHasApplicationPrefix_whenTypIsWithoutPrefix_thenValid() {
    final var validator = SpringAddonsJwtValidators.typValidator(List.of("application/at+jwt"));

    assertThat(validator.validate(jwt("at+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("application/at+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt(null)).hasErrors()).isTrue();
  }

  @Test
  void givenTypIsApplicationJwt_whenTypIsAbsent_thenValid() {
    final var validator = SpringAddonsJwtValidators.typValidator(List.of("application/jwt"));

    assertThat(validator.validate(jwt(null)).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("JWT")).hasErrors()).isFalse();
  }

  @Test
  void givenTypWithAnotherPrefix_whenValidate_thenOnlyThatValue() {
    final var validator = SpringAddonsJwtValidators.typValidator(List.of("vnd.acme/token+jwt"));

    assertThat(validator.validate(jwt("vnd.acme/token+jwt")).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("token+jwt")).hasErrors()).isTrue();
  }

  @Test
  void givenTypIsNullEmptyOrBlank_whenEffectiveTyp_thenDefault() {
    assertThat(SpringAddonsJwtValidators.effectiveTyp(null))
        .isEqualTo(OpenidProviderProperties.DEFAULT_TYP);
    assertThat(SpringAddonsJwtValidators.effectiveTyp(List.of()))
        .isEqualTo(OpenidProviderProperties.DEFAULT_TYP);
    assertThat(SpringAddonsJwtValidators.effectiveTyp(List.of(" ", "")))
        .isEqualTo(OpenidProviderProperties.DEFAULT_TYP);
  }

  @Test
  void givenTypWithBlankEntries_whenEffectiveTyp_thenTrimmedWithoutBlanks() {
    assertThat(SpringAddonsJwtValidators.effectiveTyp(List.of(" at+jwt ", "", "JWT")))
        .containsExactly("at+jwt", "JWT");
  }

  @Test
  void givenTypIsApplicationPrefixOnly_whenValidate_thenIgnoredLikeABlankEntry() {
    assertThat(SpringAddonsJwtValidators.effectiveTyp(List.of("application/")))
        .isEqualTo(OpenidProviderProperties.DEFAULT_TYP);
    assertThat(SpringAddonsJwtValidators.effectiveTyp(List.of("Application/", "at+jwt")))
        .containsExactly("at+jwt");

    final var validator = SpringAddonsJwtValidators.typValidator(List.of("application/", "at+jwt"));
    assertThat(validator.validate(jwt("application/")).hasErrors()).isTrue();
    assertThat(validator.validate(jwt("")).hasErrors()).isTrue();
    assertThat(validator.validate(jwt("at+jwt")).hasErrors()).isFalse();
  }

  @Test
  void givenAdditionalValidator_whenCreateDefault_thenItIsAppliedWithTheDefaultOnes() {
    final OAuth2TokenValidator<Jwt> validator = SpringAddonsJwtValidators.createDefault(
        Optional.of(ISSUER), Optional.of("bff"), List.of("at+jwt"),
        new JwtClaimValidator<Object>("client_id", java.util.Objects::nonNull));

    assertThat(validator.validate(jwt("at+jwt")).hasErrors()).as("no client_id").isTrue();
    assertThat(validator.validate(Jwt.withTokenValue("test").header("typ", "at+jwt")
        .claim("client_id", "bff").subject("ch4mp").issuer(ISSUER.toString())
        .audience(List.of("bff")).issuedAt(Instant.now().minusSeconds(600))
        .expiresAt(Instant.now().plusSeconds(300)).build()).hasErrors()).isFalse();
    assertThat(validator.validate(jwt("JWT")).hasErrors()).as("typ").isTrue();
  }

  @Test
  void givenNoAuthorizedParty_whenAuthorizedPartyValidator_thenEmpty() {
    for (final var parties : Arrays.<List<String>>asList(null, List.of(), List.of(" ", ""))) {
      assertThat(SpringAddonsJwtValidators.authorizedPartyValidator(parties)).as("%s", parties)
          .isEmpty();
    }
  }

  @Test
  void givenAzpListed_whenValidate_thenSuccess() {
    final var validator = authorizedParties(" gateway ", "bruno");

    assertThat(isRefused(validator, Map.of("azp", "gateway"))).isFalse();
    assertThat(isRefused(validator, Map.of("azp", "bruno"))).isFalse();
  }

  @Test
  void givenAzpNotListed_whenValidate_thenInvalidToken() {
    final var validator = authorizedParties("gateway");
    final var jwt = ResourceServerTestFixtures.jwt(Map.of("azp", "other"));

    assertThat(validator.validate(jwt).getErrors()).singleElement()
        .returns("invalid_token", OAuth2Error::getErrorCode);
    assertThat(isRefused(validator, Map.of("azp", "Gateway"))).as("case-sensitive").isTrue();
  }

  @Test
  void givenNoAzpAndClientIdListed_whenValidate_thenSuccess() {
    assertThat(isRefused(authorizedParties("gateway"), Map.of("client_id", "gateway"))).isFalse();
  }

  @Test
  void givenNullOrBlankAzp_whenValidate_thenClientIdIsChecked() {
    final var validator = authorizedParties("gateway");

    assertThat(isRefused(validator, claimsWithNullAzp(Map.of("client_id", "gateway")))).isFalse();
    assertThat(isRefused(validator, Map.of("azp", " ", "client_id", "gateway"))).isFalse();
    assertThat(isRefused(validator, claimsWithNullAzp(Map.of("client_id", "other")))).isTrue();
    assertThat(isRefused(validator, claimsWithNullAzp(Map.of("sub", "ch4mp")))).isTrue();
    assertThat(isRefused(validator, Map.of("azp", "", "sub", "ch4mp"))).isTrue();
  }

  private static Map<String, Object> claimsWithNullAzp(Map<String, Object> otherClaims) {
    final var claims = new HashMap<String, Object>(otherClaims);
    claims.put("azp", null);
    return claims;
  }

  @Test
  void givenNeitherAzpNorClientId_whenValidate_thenInvalidToken() {
    final var validator = authorizedParties("gateway");

    assertThat(isRefused(validator, Map.of("sub", "ch4mp"))).isTrue();
    assertThat(isRefused(validator, Map.of("client_id", "other"))).isTrue();
  }

  @Test
  void givenAzpNotListedAndClientIdListed_whenValidate_thenInvalidToken() {
    assertThat(isRefused(authorizedParties("gateway"),
        Map.of("azp", "other", "client_id", "gateway"))).isTrue();
  }

  @Test
  void givenValidToken_whenRequireValid_thenSameToken() {
    final var jwt = ResourceServerTestFixtures.jwt(Map.of("azp", "gateway"));

    assertThat(SpringAddonsJwtValidators.requireValid(jwt, authorizedParties("gateway")))
        .isSameAs(jwt);
  }

  @Test
  void givenInvalidToken_whenRequireValid_thenJwtValidationException() {
    final var jwt = ResourceServerTestFixtures.jwt(Map.of("azp", "other"));

    assertThatThrownBy(
        () -> SpringAddonsJwtValidators.requireValid(jwt, authorizedParties("gateway")))
            .isInstanceOf(JwtValidationException.class).hasMessage(
                "An error occurred while attempting to decode the Jwt: The token was not issued to an authorized party of this resource server");
  }

  @Test
  void givenErrorWithoutDescription_whenRequireValid_thenNimbusFallbackMessage() {
    final OAuth2TokenValidator<Jwt> validator =
        token -> OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"));
    final var jwt = ResourceServerTestFixtures.jwt(Map.of("sub", "ch4mp"));

    assertThatThrownBy(() -> SpringAddonsJwtValidators.requireValid(jwt, validator))
        .isInstanceOf(JwtValidationException.class).hasMessage("Unable to validate Jwt");
  }

  @Test
  @ExtendWith(OutputCaptureExtension.class)
  void givenOpsWithoutAud_whenWarnAboutOpsWithoutAudience_thenThoseDecodingTokensAreNamed(
      CapturedOutput output) {
    final var withIssuer = new OpenidProviderProperties();
    withIssuer.setIss(ISSUER);
    final var withJwkSetUriOnly = new OpenidProviderProperties();
    withJwkSetUriOnly.setJwkSetUri(URI.create("https://op/certs"));
    final var withAudience = new OpenidProviderProperties();
    withAudience.setIss(URI.create("https://other-op"));
    withAudience.setAud("bff");
    final var withNeitherIssuerNorJwkSetUri = new OpenidProviderProperties();

    SpringAddonsJwtValidators.warnAboutOpsWithoutAudience(
        List.of(withIssuer, withJwkSetUriOnly, withAudience, withNeitherIssuerNorJwkSetUri));

    assertThat(output)
        .contains("ops[0].aud is not set: the access tokens of https://op/realm are accepted")
        .contains("ops[1].aud is not set: the access tokens of https://op/certs are accepted")
        .doesNotContain("ops[2]").doesNotContain("ops[3]");
  }

  private static OAuth2TokenValidator<Jwt> authorizedParties(String... parties) {
    return SpringAddonsJwtValidators.authorizedPartyValidator(List.of(parties)).orElseThrow();
  }

  private static boolean isRefused(OAuth2TokenValidator<Jwt> validator,
      Map<String, Object> claims) {
    return validator.validate(ResourceServerTestFixtures.jwt(claims)).hasErrors();
  }

  private static Jwt jwt(@Nullable String typ) {
    return jwt(typ, ISSUER.toString(), "bff", false);
  }

  private static Jwt jwt(@Nullable String typ, String issuer, String audience, boolean expired) {
    final var now = Instant.now();
    final var builder = Jwt.withTokenValue("test").header("alg", "RS256").subject("ch4mp")
        .issuer(issuer).audience(List.of(audience)).issuedAt(now.minusSeconds(600))
        .expiresAt(expired ? now.minusSeconds(300) : now.plusSeconds(300));
    if (typ != null) {
      builder.header("typ", typ);
    }
    return builder.build();
  }
}
