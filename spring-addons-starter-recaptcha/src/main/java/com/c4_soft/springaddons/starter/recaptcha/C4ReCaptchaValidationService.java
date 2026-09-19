package com.c4_soft.springaddons.starter.recaptcha;

import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.rest.SystemProxyProperties;
import com.c4_soft.springaddons.rest.synchronised.SpringAddonsClientHttpRequestFactory;
import lombok.extern.slf4j.Slf4j;

/**
 * Validates reCAPTCHA tokens submitted by clients against Google's
 * <a href="https://developers.google.com/recaptcha/docs/verify">siteverify</a> endpoint. Usage:
 *
 * <pre>
 * if (!captcha.checkV2(reCaptcha)) {
 *   throw new RuntimeException("Are you a robot?");
 * }
 * </pre>
 *
 * @author Jérôme Wacongne ch4mp&#64;c4-soft.com
 */
@Slf4j
public class C4ReCaptchaValidationService {

  private final RestClient client;
  private final String googleRecaptchaSecret;
  private final double v3Threshold;

  /**
   * @param settings reCAPTCHA settings ({@code secret-key} and {@code v3-threshold} are read from
   *        it)
   * @param client the client to send verification requests with: its base URL must be the
   *        siteverify endpoint
   */
  public C4ReCaptchaValidationService(C4ReCaptchaSettings settings, RestClient client) {
    Assert.hasText(settings.getSecretKey(),
        "com.c4-soft.springaddons.recaptcha.secret-key must be set (see https://www.google.com/recaptcha/admin/site)");
    this.client = client;
    this.googleRecaptchaSecret = settings.getSecretKey();
    this.v3Threshold = settings.getV3Threshold();
  }

  /**
   * @param settings reCAPTCHA settings
   * @param systemProxyProperties {@code http_proxy} / {@code no_proxy} environment variables
   * @param restClientBuilder the application {@link RestClient.Builder} (Spring Boot auto-configures
   *        one, with the application's message converters and observation), or null to use a
   *        default builder
   */
  public C4ReCaptchaValidationService(C4ReCaptchaSettings settings,
      SystemProxyProperties systemProxyProperties,
      RestClient.@Nullable Builder restClientBuilder) {
    this(settings, restClient(settings, systemProxyProperties, restClientBuilder));
  }

  public C4ReCaptchaValidationService(C4ReCaptchaSettings settings,
      SystemProxyProperties systemProxyProperties) {
    this(settings, systemProxyProperties, null);
  }

  private static RestClient restClient(C4ReCaptchaSettings settings,
      SystemProxyProperties systemProxyProperties,
      RestClient.@Nullable Builder restClientBuilder) {
    Assert.notNull(settings.getSiteverifyUrl(),
        "com.c4-soft.springaddons.recaptcha.siteverify-url must be set");
    return (restClientBuilder == null ? RestClient.builder() : restClientBuilder.clone())
        .requestFactory(
            new SpringAddonsClientHttpRequestFactory(systemProxyProperties, settings.getHttp()))
        .baseUrl(settings.getSiteverifyUrl().toString()).build();
  }

  /**
   * Checks a reCAPTCHA v2 challenge response
   *
   * @param response answer provided by the client
   * @return true if the token was valid for your site
   */
  public Boolean checkV2(String response) {
    final var dto = response(response, V2ValidationResponseDto.class);
    log.debug("reCaptcha result : {}", dto);
    return dto.isSuccess();
  }

  /**
   * Checks a reCAPTCHA v3 challenge response
   *
   * @param response answer provided by the client
   * @return a score between 0 and 1
   * @throws ReCaptchaValidationException if the response wasn't a valid reCAPTCHA token for your
   *         site or if the score is below the configured threshold
   */
  public Double checkV3(String response) throws ReCaptchaValidationException {
    return checkV3(response, null);
  }

  /**
   * Checks a reCAPTCHA v3 challenge response, including the action it was generated for (as
   * <a href="https://developers.google.com/recaptcha/docs/v3#interpreting_the_score">recommended by
   * Google</a>: without it, a token obtained for any action of your site is accepted)
   *
   * @param response answer provided by the client
   * @param expectedAction the action name the token must have been generated for, or null to skip
   *        that check
   * @return a score between 0 and 1
   * @throws ReCaptchaValidationException if the response wasn't a valid reCAPTCHA token for your
   *         site, was generated for another action, or if the score is below the configured
   *         threshold
   */
  public Double checkV3(String response, @Nullable String expectedAction)
      throws ReCaptchaValidationException {
    final var dto = response(response, V3ValidationResponseDto.class);
    log.debug("reCaptcha result : {}", dto);
    if (!dto.isSuccess()) {
      throw new ReCaptchaValidationException(
          "Invalid reCAPTCHA token. Error codes: %s".formatted(dto.getErrorCodes()));
    }
    if (expectedAction != null && !Objects.equals(expectedAction, dto.getAction())) {
      throw new ReCaptchaValidationException("reCAPTCHA token was generated for action '%s', not '%s'"
          .formatted(dto.getAction(), expectedAction));
    }
    final var score = Optional.ofNullable(dto.getScore()).orElse(0.);
    if (score < v3Threshold) {
      throw new ReCaptchaValidationException(
          "reCAPTCHA score %s is below the configured threshold %s".formatted(score, v3Threshold));
    }
    return score;
  }

  private <T extends V2ValidationResponseDto> T response(String response, Class<T> dtoType) {
    final var formData = new LinkedMultiValueMap<String, String>();
    formData.add("secret", googleRecaptchaSecret);
    formData.add("response", response);
    final var dto = client.post().contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .body(formData).retrieve().body(dtoType);
    if (dto == null) {
      throw new ReCaptchaValidationException("Empty response from the reCAPTCHA siteverify endpoint");
    }
    return dto;
  }
}
