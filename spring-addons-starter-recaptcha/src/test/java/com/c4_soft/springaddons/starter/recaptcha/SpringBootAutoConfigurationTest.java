package com.c4_soft.springaddons.starter.recaptcha;

import static org.assertj.core.api.Assertions.assertThat;
import java.net.URI;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.NestedExceptionUtils;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

class SpringBootAutoConfigurationTest {

  private final ApplicationContextRunner runner = new ApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringBootAutoConfiguration.class));

  @Test
  void givenOnlySecretKey_whenStart_thenServiceIsAvailableWithDefaults() {
    runner.withPropertyValues("com.c4-soft.springaddons.recaptcha.secret-key=machin").run(ctx -> {
      assertThat(ctx).hasNotFailed();
      assertThat(ctx).hasSingleBean(C4ReCaptchaValidationService.class);
      final var settings = ctx.getBean(C4ReCaptchaSettings.class);
      assertThat(settings.getSiteverifyUrl())
          .isEqualTo(URI.create("https://www.google.com/recaptcha/api/siteverify"));
      assertThat(settings.getV3Threshold()).isEqualTo(.5);
      assertThat(settings.getHttp()).isNotNull();
      assertThat(settings.toString()).doesNotContain("machin");
    });
  }

  @Test
  void givenNoSecretKey_whenStart_thenFailsWithExplicitMessage() {
    runner.run(ctx -> {
      assertThat(ctx).hasFailed();
      assertThat(NestedExceptionUtils.getMostSpecificCause(ctx.getStartupFailure()))
          .hasMessageContaining("com.c4-soft.springaddons.recaptcha.secret-key");
    });
  }

  @Test
  void givenAllProperties_whenStart_thenBound() {
    runner.withPropertyValues("com.c4-soft.springaddons.recaptcha.secret-key=machin",
        "com.c4-soft.springaddons.recaptcha.siteverify-url=https://localhost/siteverify",
        "com.c4-soft.springaddons.recaptcha.v3-threshold=0.8",
        "com.c4-soft.springaddons.recaptcha.http.proxy.host=corp-proxy",
        "com.c4-soft.springaddons.recaptcha.http.connect-timeout-millis=500").run(ctx -> {
          assertThat(ctx).hasNotFailed();
          final var settings = ctx.getBean(C4ReCaptchaSettings.class);
          assertThat(settings.getSiteverifyUrl())
              .isEqualTo(URI.create("https://localhost/siteverify"));
          assertThat(settings.getV3Threshold()).isEqualTo(.8);
          assertThat(settings.getHttp().getProxy().getHost()).contains("corp-proxy");
          assertThat(settings.getHttp().getConnectTimeoutMillis()).contains(500);
        });
  }

  @Test
  void givenUserDefinedService_whenStart_thenAutoConfiguredOneBacksOff() {
    runner.withPropertyValues("com.c4-soft.springaddons.recaptcha.secret-key=machin")
        .withBean("custom", C4ReCaptchaValidationService.class,
            () -> new C4ReCaptchaValidationService(settings("other"),
                new SystemProxyProperties()))
        .run(ctx -> {
          assertThat(ctx).hasNotFailed();
          assertThat(ctx).hasSingleBean(C4ReCaptchaValidationService.class);
          assertThat(ctx).hasBean("custom");
        });
  }

  static C4ReCaptchaSettings settings(String secretKey) {
    final var settings = new C4ReCaptchaSettings();
    settings.setSecretKey(secretKey);
    return settings;
  }
}
