package com.c4_soft.springaddons.rest.reactive;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;

class SpringAddonsServerWebClientBeansConditionsTest {

  private static final String CLIENT_PROPERTY =
      "com.c4-soft.springaddons.rest.client.echo-client.base-url=http://localhost:1";
  private static final String GROUP_PROPERTY =
      "com.c4-soft.springaddons.rest.group.echo-group.client=echo-client";

  private final ReactiveWebApplicationContextRunner contextRunner =
      new ReactiveWebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(SpringAddonsRestProperties.class,
              SpringAddonsServerWebClientBeans.class))
          .withPropertyValues(CLIENT_PROPERTY);

  @Test
  void givenGroupPropertyMissing_whenContextStarts_thenConfigurerBeanIsAbsent() {
    contextRunner.run(context -> assertThat(context)
        .doesNotHaveBean(SpringAddonsServerWebClientHttpServiceGroupConfigurer.class)
        .doesNotHaveBean("springAddonsWebClientHttpServiceGroupConfigurer"));
  }

  @Test
  void givenNonEmptyGroupProperty_whenContextStarts_thenConfigurerBeanIsPresent() {
    contextRunner.withPropertyValues(GROUP_PROPERTY).run(context -> assertThat(context)
        .hasSingleBean(SpringAddonsServerWebClientHttpServiceGroupConfigurer.class)
        .hasBean("springAddonsWebClientHttpServiceGroupConfigurer"));
  }

  @Test
  void givenUserDefinedConfigurer_whenContextStarts_thenAutoConfigurationBacksOff() {
    contextRunner.withPropertyValues(GROUP_PROPERTY)
        .withUserConfiguration(UserServerWebClientConfigurerConfiguration.class)
        .run(context -> assertThat(context)
            .hasSingleBean(SpringAddonsServerWebClientHttpServiceGroupConfigurer.class)
            .hasBean("userServerWebClientHttpServiceGroupConfigurer")
            .doesNotHaveBean("springAddonsWebClientHttpServiceGroupConfigurer"));
  }

  @Configuration
  static class UserServerWebClientConfigurerConfiguration {

    @Bean
    SpringAddonsServerWebClientHttpServiceGroupConfigurer userServerWebClientHttpServiceGroupConfigurer(
        SpringAddonsRestProperties restProperties, ApplicationContext applicationContext) {
      return new SpringAddonsServerWebClientHttpServiceGroupConfigurer(restProperties,
          applicationContext);
    }
  }
}
