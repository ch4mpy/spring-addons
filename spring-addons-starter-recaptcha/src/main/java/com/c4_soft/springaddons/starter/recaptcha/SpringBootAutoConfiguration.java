package com.c4_soft.springaddons.starter.recaptcha;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

/**
 * Exposes a {@link C4ReCaptchaValidationService} bean configured with
 * {@code com.c4-soft.springaddons.recaptcha.*} properties. Both can be overridden by defining a
 * bean of the same type.
 */
@AutoConfiguration
@EnableConfigurationProperties(C4ReCaptchaSettings.class)
public class SpringBootAutoConfiguration {

  @ConditionalOnMissingBean
  @Bean
  C4ReCaptchaValidationService c4ReCaptchaValidationService(C4ReCaptchaSettings settings,
      Environment environment, ObjectProvider<RestClient.Builder> restClientBuilder) {
    return new C4ReCaptchaValidationService(settings,
        SystemProxyProperties.fromEnvironment(environment), restClientBuilder.getIfUnique());
  }
}
