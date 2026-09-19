package com.c4_soft.springaddons.starter.recaptcha;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import lombok.Data;
import lombok.ToString;

/**
 * Configuration for {@link C4ReCaptchaValidationService}
 */
@Data
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.recaptcha")
public class C4ReCaptchaSettings {

  /**
   * Secret key from https://www.google.com/recaptcha/admin/site (required)
   */
  @ToString.Exclude
  private String secretKey;

  /**
   * URL of the endpoint verifying submitted reCAPTCHA tokens
   */
  private URI siteverifyUrl = URI.create("https://www.google.com/recaptcha/api/siteverify");

  /**
   * Minimum reCAPTCHA v3 score (0.0 - 1.0) under which a validation exception is thrown
   */
  private double v3Threshold = .5;

  /**
   * HTTP client configuration for requests to the siteverify endpoint: proxy, timeouts, SSL, etc.
   * (same properties as com.c4-soft.springaddons.rest.client.*.http)
   */
  @NestedConfigurationProperty
  private ClientHttpRequestFactoryProperties http = new ClientHttpRequestFactoryProperties();

}
