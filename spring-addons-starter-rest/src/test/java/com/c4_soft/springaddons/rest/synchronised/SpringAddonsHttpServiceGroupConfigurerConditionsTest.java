package com.c4_soft.springaddons.rest.synchronised;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;

class SpringAddonsHttpServiceGroupConfigurerConditionsTest {

  private static final String CLIENT_PROPERTY =
      "com.c4-soft.springaddons.rest.client.echo-client.base-url=http://localhost:1";
  private static final String GROUP_PROPERTY =
      "com.c4-soft.springaddons.rest.group.echo-group.client=echo-client";

  private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringAddonsRestProperties.class,
          SpringAddonsRestClientBeans.class, SpringAddonsServletWebClientBeans.class))
      .withPropertyValues(CLIENT_PROPERTY);

  @Test
  void givenGroupPropertyMissing_whenContextStarts_thenConfigurerBeansAreAbsent() {
    contextRunner.run(context -> assertThat(context)
        .doesNotHaveBean(SpringAddonsRestClientHttpServiceGroupConfigurer.class)
        .doesNotHaveBean(SpringAddonsServletWebClientHttpServiceGroupConfigurer.class)
        .doesNotHaveBean("springAddonsRestClientHttpServiceGroupConfigurer")
        .doesNotHaveBean("springAddonsWebClientHttpServiceGroupConfigurer"));
  }

  @Test
  void givenNonEmptyGroupProperty_whenContextStarts_thenConfigurerBeansArePresent() {
    contextRunner.withPropertyValues(GROUP_PROPERTY).run(context -> assertThat(context)
        .hasSingleBean(SpringAddonsRestClientHttpServiceGroupConfigurer.class)
        .hasSingleBean(SpringAddonsServletWebClientHttpServiceGroupConfigurer.class)
        .hasBean("springAddonsRestClientHttpServiceGroupConfigurer")
        .hasBean("springAddonsWebClientHttpServiceGroupConfigurer"));
  }

  @Test
  void givenUserDefinedRestClientConfigurer_whenContextStarts_thenAutoConfigurationBacksOff() {
    contextRunner.withPropertyValues(GROUP_PROPERTY)
        .withUserConfiguration(UserRestClientConfigurerConfiguration.class)
        .run(context -> assertThat(context)
            .hasSingleBean(SpringAddonsRestClientHttpServiceGroupConfigurer.class)
            .hasBean("userRestClientHttpServiceGroupConfigurer")
            .doesNotHaveBean("springAddonsRestClientHttpServiceGroupConfigurer"));
  }

  @Test
  void givenUserDefinedServletWebClientConfigurer_whenContextStarts_thenAutoConfigurationBacksOff() {
    contextRunner.withPropertyValues(GROUP_PROPERTY)
        .withUserConfiguration(UserServletWebClientConfigurerConfiguration.class)
        .run(context -> assertThat(context)
            .hasSingleBean(SpringAddonsServletWebClientHttpServiceGroupConfigurer.class)
            .hasBean("userServletWebClientHttpServiceGroupConfigurer")
            .doesNotHaveBean("springAddonsWebClientHttpServiceGroupConfigurer"));
  }

  @Configuration
  static class UserRestClientConfigurerConfiguration {

    @Bean
    SpringAddonsRestClientHttpServiceGroupConfigurer userRestClientHttpServiceGroupConfigurer(
        SpringAddonsRestProperties restProperties, ApplicationContext applicationContext) {
      return new SpringAddonsRestClientHttpServiceGroupConfigurer(restProperties,
          applicationContext);
    }
  }

  @Configuration
  static class UserServletWebClientConfigurerConfiguration {

    @Bean
    SpringAddonsServletWebClientHttpServiceGroupConfigurer userServletWebClientHttpServiceGroupConfigurer(
        SpringAddonsRestProperties restProperties, ApplicationContext applicationContext) {
      return new SpringAddonsServletWebClientHttpServiceGroupConfigurer(restProperties,
          applicationContext);
    }
  }
}
