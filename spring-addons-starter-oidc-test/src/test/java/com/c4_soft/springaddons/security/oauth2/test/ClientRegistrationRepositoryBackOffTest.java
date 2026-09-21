package com.c4_soft.springaddons.security.oauth2.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AddonsWebfluxTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcTestConf;

/**
 * The mocked client registration repository of the test slices must back off for any
 * {@link ClientRegistrationRepository} (or reactive) bean of the application, not only for an
 * in-memory one: with two repositories, the beans injecting one by type either fail or silently
 * take the mock.
 */
class ClientRegistrationRepositoryBackOffTest {

  private final WebApplicationContextRunner servletRunner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(AddonsWebmvcTestConf.class));

  private final ReactiveWebApplicationContextRunner reactiveRunner =
      new ReactiveWebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(AddonsWebfluxTestConf.class))
          .withPropertyValues(
              "com.c4-soft.springaddons.oidc.ops[0].iss=https://localhost:8443/realms/test");

  @Test
  void givenNoRepositoryBean_thenMockIsCreated() {
    servletRunner.run(context -> assertThat(context)
        .hasSingleBean(InMemoryClientRegistrationRepository.class));
    reactiveRunner.run(context -> assertThat(context)
        .hasSingleBean(InMemoryReactiveClientRegistrationRepository.class));
  }

  @Test
  void givenRepositoryBeanOfAnotherType_thenMockBacksOff() {
    servletRunner.withUserConfiguration(CustomServletRepository.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).hasSingleBean(ClientRegistrationRepository.class);
      assertThat(context).doesNotHaveBean(InMemoryClientRegistrationRepository.class);
    });
    reactiveRunner.withUserConfiguration(CustomReactiveRepository.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).hasSingleBean(ReactiveClientRegistrationRepository.class);
      assertThat(context).doesNotHaveBean(InMemoryReactiveClientRegistrationRepository.class);
    });
  }

  @Configuration
  static class CustomServletRepository {
    @Bean
    ClientRegistrationRepository customClientRegistrationRepository() {
      return mock(ClientRegistrationRepository.class);
    }
  }

  @Configuration
  static class CustomReactiveRepository {
    @Bean
    ReactiveClientRegistrationRepository customClientRegistrationRepository() {
      return mock(ReactiveClientRegistrationRepository.class);
    }
  }
}
