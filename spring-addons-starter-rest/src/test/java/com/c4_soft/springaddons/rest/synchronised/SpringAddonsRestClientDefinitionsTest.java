package com.c4_soft.springaddons.rest.synchronised;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;
import com.c4_soft.springaddons.rest.reactive.ServerWebClientFactoryBean;

/**
 * The REST client definitions don't hold the properties: the clients bind them from the environment
 * when they are created, whatever the {@link SystemProxyProperties} or
 * {@link SpringAddonsRestProperties} beans of the application (gh-341).
 */
class SpringAddonsRestClientDefinitionsTest {

  private final WebApplicationContextRunner servletRunner = new WebApplicationContextRunner()
      .withUserConfiguration(ApplicationConfiguration.class).withPropertyValues(
          "com.c4-soft.springaddons.rest.client.foo-client.base-url=https://foo",
          "com.c4-soft.springaddons.rest.client.bar-client.base-url=https://bar",
          "com.c4-soft.springaddons.rest.client.bar-client.type=web-client");

  private final ReactiveWebApplicationContextRunner reactiveRunner =
      new ReactiveWebApplicationContextRunner()
          .withUserConfiguration(ApplicationConfiguration.class)
          .withPropertyValues("com.c4-soft.springaddons.rest.client.baz-client.base-url=https://baz");

  @Test
  void givenServletAppWithAnotherSystemProxyPropertiesBean_whenStart_thenClientsAreCreatedWithoutTheBeans() {
    servletRunner.withUserConfiguration(AnotherSystemProxyPropertiesConfiguration.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).getBeans(SystemProxyProperties.class).hasSize(2);
          assertThat(context.getBean("fooClient", RestClient.class)).isNotNull();
          assertThat(context.getBean("barClient", WebClient.class)).isNotNull();
          assertThat(context.getBean("&fooClient", RestClientFactoryBean.class))
              .extracting("systemProxyProperties", "restProperties").containsOnlyNulls();
          assertThat(context.getBean("&barClient", ServletWebClientFactoryBean.class))
              .extracting("systemProxyProperties", "restProperties").containsOnlyNulls();
        });
  }

  @Test
  void givenServletAppWithAnotherSpringAddonsRestPropertiesBean_whenStart_thenClientsAreCreated() {
    servletRunner.withUserConfiguration(AnotherRestPropertiesConfiguration.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).getBeans(SpringAddonsRestProperties.class).hasSize(2);
      assertThat(context.getBean("fooClient", RestClient.class)).isNotNull();
      assertThat(context.getBean("barClient", WebClient.class)).isNotNull();
    });
  }

  @Test
  void givenReactiveAppWithAnotherBeanOfEachType_whenStart_thenClientIsCreatedWithoutTheBeans() {
    reactiveRunner.withUserConfiguration(AnotherSystemProxyPropertiesConfiguration.class,
        AnotherRestPropertiesConfiguration.class).run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).getBeans(SystemProxyProperties.class).hasSize(2);
          assertThat(context).getBeans(SpringAddonsRestProperties.class).hasSize(2);
          assertThat(context.getBean("bazClient", WebClient.class)).isNotNull();
          assertThat(context.getBean("&bazClient", ServerWebClientFactoryBean.class))
              .extracting("systemProxyProperties", "restProperties").containsOnlyNulls();
        });
  }

  @Configuration(proxyBeanMethods = false)
  @EnableAutoConfiguration
  static class ApplicationConfiguration {
  }

  @Configuration(proxyBeanMethods = false)
  static class AnotherSystemProxyPropertiesConfiguration {
    @Bean
    SystemProxyProperties corpProxy() {
      return new SystemProxyProperties(Optional.of("http://corp-proxy:3128"), List.of());
    }
  }

  @Configuration(proxyBeanMethods = false)
  static class AnotherRestPropertiesConfiguration {
    @Bean
    SpringAddonsRestProperties otherRestProperties() {
      return new SpringAddonsRestProperties();
    }
  }
}
