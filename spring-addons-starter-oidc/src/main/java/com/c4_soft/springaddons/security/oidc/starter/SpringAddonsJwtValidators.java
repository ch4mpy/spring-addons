package com.c4_soft.springaddons.security.oidc.starter;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtAudienceValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;
import lombok.extern.slf4j.Slf4j;

/**
 * The {@link OAuth2TokenValidator} set by the default JWT decoder factories, built from the OpenID
 * Provider properties of the token issuer: Spring Security defaults (timestamps, X.509 thumbprint),
 * the {@code typ} header, and, when configured, the issuer and the audience. Also the authorized
 * parties validator, which the auto-configured authentication manager resolvers apply to the
 * tokens decoded by any factory, and their startup warning about OpenID Providers without
 * audience.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public final class SpringAddonsJwtValidators {

  private static final String APPLICATION_PREFIX = "application/";

  private static final OAuth2Error UNAUTHORIZED_PARTY = new OAuth2Error(
      OAuth2ErrorCodes.INVALID_TOKEN,
      "The token was not issued to an authorized party of this resource server",
      "https://tools.ietf.org/html/rfc6750#section-3.1");

  private SpringAddonsJwtValidators() {}

  /**
   * @param issuer the expected {@code iss} claim, if any
   * @param audience a value the {@code aud} claim must contain, if any
   * @param typ the accepted {@code typ} header values, see {@link #typValidator(List)}
   * @param additionalValidators validators to apply too, for instance a {@code JwtClaimValidator}
   *        for a claim RFC 9068 requires ({@code client_id}, {@code jti}, ...)
   * @return the Spring Security default validators, with the {@code typ} validator for the given
   *         values instead of the default one, plus an issuer validator and an audience validator
   *         when the corresponding parameter is present, plus the additional validators
   */
  @SafeVarargs
  public static OAuth2TokenValidator<Jwt> createDefault(Optional<URI> issuer,
      Optional<String> audience, @Nullable List<String> typ,
      OAuth2TokenValidator<Jwt>... additionalValidators) {
    final List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
    validators.add(typValidator(typ));
    issuer.map(URI::toString).map(JwtIssuerValidator::new).ifPresent(validators::add);
    audience.filter(StringUtils::hasText).map(JwtAudienceValidator::new)
        .ifPresent(validators::add);
    validators.addAll(List.of(additionalValidators));
    return JwtValidators.createDefaultWithValidators(validators);
  }

  /**
   * @param typ the configured {@code typ} values
   * @return the configured values, trimmed and without blank entries (nor entries made of the
   *         {@code application/} prefix only), or {@link OpenidProviderProperties#DEFAULT_TYP}
   *         when none is left (null, empty or blank configuration)
   */
  public static List<String> effectiveTyp(@Nullable List<String> typ) {
    final var configured = nonBlankTrimmed(typ)
        .filter(value -> !APPLICATION_PREFIX.equalsIgnoreCase(value)).toList();
    return configured.isEmpty() ? OpenidProviderProperties.DEFAULT_TYP : configured;
  }

  /**
   * @param authorizedParties the client IDs the tokens must have been issued to, compared exactly
   *        once trimmed (blank entries are ignored)
   * @return empty when no client ID is left, or else a validator accepting a token whose
   *         {@code azp} claim is one of them or, for a token without {@code azp} value, whose
   *         {@code client_id} claim is one of them: a token with an {@code azp} which is not listed
   *         is refused, whatever its {@code client_id}
   */
  public static Optional<OAuth2TokenValidator<Jwt>> authorizedPartyValidator(
      @Nullable List<String> authorizedParties) {
    final var accepted = nonBlankTrimmed(authorizedParties).collect(Collectors.toUnmodifiableSet());
    if (accepted.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(jwt -> {
      final var azp = jwt.getClaimAsString(IdTokenClaimNames.AZP);
      final var party =
          azp != null ? azp : jwt.getClaimAsString(OAuth2TokenIntrospectionClaimNames.CLIENT_ID);
      return party != null && accepted.contains(party) ? OAuth2TokenValidatorResult.success()
          : OAuth2TokenValidatorResult.failure(UNAUTHORIZED_PARTY);
    });
  }

  /**
   * @param jwt a decoded token
   * @param validator a validator to apply on top of the decoder's
   * @return the token, when the validator accepts it
   * @throws JwtValidationException otherwise, with the message {@code NimbusJwtDecoder} builds for
   *         the same errors: the authentication managers turn it into an
   *         {@code InvalidBearerTokenException}
   */
  public static Jwt requireValid(Jwt jwt, OAuth2TokenValidator<Jwt> validator) {
    final var result = validator.validate(jwt);
    if (!result.hasErrors()) {
      return jwt;
    }
    final var message = result.getErrors().stream().map(OAuth2Error::getDescription)
        .filter(StringUtils::hasLength).findFirst()
        .map("An error occurred while attempting to decode the Jwt: %s"::formatted)
        .orElse("Unable to validate Jwt");
    throw new JwtValidationException(message, result.getErrors());
  }

  /**
   * Logs a warning for each OpenID Provider without {@code aud}: the auto-configured decoders then
   * accept its access tokens whatever their audience (RFC 9068, section 4).
   *
   * @param ops the configured OpenID Providers
   */
  public static void warnAboutOpsWithoutAudience(List<OpenidProviderProperties> ops) {
    for (var i = 0; i < ops.size(); ++i) {
      final var op = ops.get(i);
      if (!StringUtils.hasText(op.getAud())) {
        log.warn(
            "com.c4-soft.springaddons.oidc.ops[{}].aud is not set: the access tokens of {} are accepted whatever their audience (RFC 9068, section 4)",
            i, nameOf(op));
      }
    }
  }

  private static Object nameOf(OpenidProviderProperties op) {
    if (op.getIss() != null) {
      return op.getIss();
    }
    return op.getJwkSetUri() != null ? op.getJwkSetUri() : "this OpenID Provider";
  }

  private static Stream<String> nonBlankTrimmed(@Nullable List<String> values) {
    return Optional.ofNullable(values).orElse(List.of()).stream().filter(StringUtils::hasText)
        .map(String::trim);
  }

  /**
   * @param typ the accepted {@code typ} header values, compared case-insensitively, see
   *        {@link #effectiveTyp(List)} for null, empty and blank entries. As required by RFC 7515
   *        section 4.1.9, a value without {@code /} is also accepted with an {@code application/}
   *        prefix and the other way around: {@code at+jwt} and {@code application/at+jwt} are the
   *        same media type.
   * @return a validator accepting the given values, and a missing or blank {@code typ} header only
   *         when {@code JWT} (or {@code application/jwt}) is one of them
   */
  public static JwtTypeValidator typValidator(@Nullable List<String> typ) {
    final var accepted = effectiveTyp(typ).stream()
        .flatMap(SpringAddonsJwtValidators::mediaTypeSpellings).distinct().toList();
    final var validator = new JwtTypeValidator(accepted);
    validator.setAllowEmpty(accepted.stream().anyMatch("JWT"::equalsIgnoreCase));
    return validator;
  }

  /**
   * @param typ a non-blank {@code typ} value, other than the {@code application/} prefix alone
   * @return {@code typ} and its other spelling: with the {@code application/} prefix when it has no
   *         {@code /}, without it when the rest has no {@code /}
   */
  private static Stream<String> mediaTypeSpellings(String typ) {
    if (!typ.contains("/")) {
      return Stream.of(typ, APPLICATION_PREFIX + typ);
    }
    final var hasPrefix =
        typ.regionMatches(true, 0, APPLICATION_PREFIX, 0, APPLICATION_PREFIX.length());
    final var subtype = hasPrefix ? typ.substring(APPLICATION_PREFIX.length()) : "";
    return StringUtils.hasText(subtype) && !subtype.contains("/") ? Stream.of(subtype, typ)
        : Stream.of(typ);
  }
}
