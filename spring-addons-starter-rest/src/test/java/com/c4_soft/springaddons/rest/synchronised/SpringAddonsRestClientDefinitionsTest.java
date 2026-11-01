package com.c4_soft.springaddons.rest.synchronised;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

/**
 * The REST client definitions don't hold the properties: the clients bind them from the environment
 * when they are created, whatever the {@link SystemProxyProperties} or
 * {@link SpringAddonsRestProperties} beans of the application (gh-341).
 */
class SpringAddonsRestClientDefinitionsTest {

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withUserConfiguration(ApplicationConfiguration.class)
      .withPropertyValues("com.c4-soft.springaddons.rest.client.foo-client.base-url=https://foo",
          "http-proxy=http://env-proxy:8080");

  @Test
  void givenAnotherSystemProxyPropertiesBean_whenStart_thenClientIsCreatedWithTheEnvironmentProxy() {
    runner.withUserConfiguration(AnotherSystemProxyPropertiesConfiguration.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).getBeans(SystemProxyProperties.class).hasSize(2);
      assertThat(context.getBean("fooClient", RestClient.class)).isNotNull();

      final var factoryBean = context.getBean("&fooClient", RestClientFactoryBean.class);
      assertThat(factoryBean).extracting("systemProxyProperties").isNull();
      assertThat(SystemProxyProperties.fromEnvironment(context.getEnvironment()).getHttpProxy())
          .hasValueSatisfying(url -> assertThat(url.toString()).isEqualTo("http://env-proxy:8080"));
    });
  }

  @Test
  void givenAnotherSpringAddonsRestPropertiesBean_whenStart_thenClientIsCreated() {
    runner.withUserConfiguration(AnotherRestPropertiesConfiguration.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).getBeans(SpringAddonsRestProperties.class).hasSize(2);
      assertThat(context.getBean("fooClient", RestClient.class)).isNotNull();
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
