package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.server.SecurityWebFilterChain;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ReactiveSpringAddonsOidcResourceServerBeans;
import reactor.core.publisher.Mono;

/**
 * Reactive twin of {@link JwtAuthenticationConverterSelectionTest}.
 */
class ReactiveJwtAuthenticationConverterSelectionTest {
  private static final String DEFAULT_JWT_CONVERTER = "jwtAuthenticationConverter";
  private static final String DEFAULT_INTROSPECTION_CONVERTER = "introspectionAuthenticationConverter";

  private final ReactiveWebApplicationContextRunner jwtRunner =
      new ReactiveWebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(SpringAddonsOidcProperties.class,
              ReactiveSpringAddonsOidcResourceServerBeans.class, ServerProperties.class))
          .withPropertyValues(
              "com.c4-soft.springaddons.oidc.ops[0].iss=https://localhost:8443/realms/test");

  private final ReactiveWebApplicationContextRunner introspectionRunner =
      new ReactiveWebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(SpringAddonsOidcProperties.class,
              OAuth2ResourceServerProperties.class,
              ReactiveSpringAddonsOidcResourceServerBeans.class, ServerProperties.class))
          .withBean(ReactiveOpaqueTokenIntrospector.class,
              () -> mock(ReactiveOpaqueTokenIntrospector.class))
          .withPropertyValues(
              "com.c4-soft.springaddons.oidc.ops[0].iss=https://localhost:8443/realms/test",
              "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri=https://localhost:8443/realms/test/protocol/openid-connect/token/introspect");

  @Test
  void givenNoConverterBean_thenDefaultIsCreated() {
    jwtRunner.run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).hasBean(DEFAULT_JWT_CONVERTER);
      assertThat(context).hasSingleBean(ReactiveAuthenticationManagerResolver.class);
    });
  }

  @Test
  void givenReactiveJwtAuthenticationConverterBeanWithAnotherName_thenDefaultBacksOff() {
    jwtRunner.withUserConfiguration(SingleConverterWithAnotherName.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).doesNotHaveBean(DEFAULT_JWT_CONVERTER);
      assertThat(context).hasBean("defaultJwtAuthenticationConverter");
      assertThat(context).hasSingleBean(ReactiveAuthenticationManagerResolver.class);
      assertThat(context).hasSingleBean(SecurityWebFilterChain.class);
    });
  }

  @Test
  void givenConverterBeanToAMonoOfJwtAuthenticationTokenSubtype_thenDefaultBacksOff() {
    jwtRunner.withUserConfiguration(SingleConverterToSubtype.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).doesNotHaveBean(DEFAULT_JWT_CONVERTER);
      assertThat(context).hasSingleBean(ReactiveAuthenticationManagerResolver.class);
    });
  }

  @Test
  void givenTwoConverterBeansOnePrimary_thenContextStarts() {
    jwtRunner.withUserConfiguration(TwoConvertersOnePrimary.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).doesNotHaveBean(DEFAULT_JWT_CONVERTER);
      assertThat(context).hasSingleBean(ReactiveAuthenticationManagerResolver.class);
    });
  }

  @Test
  void givenTwoConverterBeansOneWithDefaultName_thenContextStarts() {
    jwtRunner.withUserConfiguration(TwoConvertersOneWithDefaultName.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).hasSingleBean(ReactiveAuthenticationManagerResolver.class);
    });
  }

  @Test
  void givenTwoConverterBeansNeitherPrimaryNorDefaultName_thenContextFails() {
    jwtRunner.withUserConfiguration(TwoConvertersWithoutPreference.class).run(context -> {
      assertThat(context).hasFailed();
      assertThat(context).getFailure().hasRootCauseInstanceOf(NoUniqueBeanDefinitionException.class)
          .rootCause().hasMessageContaining("converterA").hasMessageContaining("converterB");
    });
  }

  @Test
  void givenNoIntrospectionConverterBean_thenDefaultIsCreated() {
    introspectionRunner.run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).hasBean(DEFAULT_INTROSPECTION_CONVERTER);
    });
  }

  @Test
  void givenTwoIntrospectionConverterBeansOnePrimary_thenContextStarts() {
    introspectionRunner.withUserConfiguration(TwoIntrospectionConvertersOnePrimary.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).doesNotHaveBean(DEFAULT_INTROSPECTION_CONVERTER);
          assertThat(context).hasSingleBean(SecurityWebFilterChain.class);
        });
  }

  @Test
  void givenTwoIntrospectionConverterBeansOneWithDefaultName_thenContextStarts() {
    introspectionRunner.withUserConfiguration(TwoIntrospectionConvertersOneWithDefaultName.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).hasSingleBean(SecurityWebFilterChain.class);
        });
  }

  @Test
  void givenTwoIntrospectionConverterBeansWithoutPreference_thenContextFails() {
    introspectionRunner.withUserConfiguration(TwoIntrospectionConvertersWithoutPreference.class)
        .run(context -> {
          assertThat(context).hasFailed();
          assertThat(context).getFailure()
              .hasRootCauseInstanceOf(NoUniqueBeanDefinitionException.class);
        });
  }

  @Configuration
  static class SingleConverterWithAnotherName {
    @Bean
    ReactiveJwtAuthenticationConverter defaultJwtAuthenticationConverter() {
      return new ReactiveJwtAuthenticationConverter();
    }
  }

  @Configuration
  static class SingleConverterToSubtype {
    @Bean
    Converter<Jwt, Mono<JwtAuthenticationToken>> converterToSubtype() {
      return jwt -> Mono.just(new JwtAuthenticationToken(jwt, List.of()));
    }
  }

  @Configuration
  static class TwoConvertersOnePrimary {
    @Bean
    @Primary
    ReactiveJwtAuthenticationConverter converterA() {
      return new ReactiveJwtAuthenticationConverter();
    }

    @Bean
    ReactiveJwtAuthenticationConverter converterB() {
      return new ReactiveJwtAuthenticationConverter();
    }
  }

  @Configuration
  static class TwoConvertersOneWithDefaultName {
    @Bean
    ReactiveJwtAuthenticationConverter converterA() {
      return new ReactiveJwtAuthenticationConverter();
    }

    @Bean
    ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
      return new ReactiveJwtAuthenticationConverter();
    }
  }

  @Configuration
  static class TwoConvertersWithoutPreference {
    @Bean
    ReactiveJwtAuthenticationConverter converterA() {
      return new ReactiveJwtAuthenticationConverter();
    }

    @Bean
    ReactiveJwtAuthenticationConverter converterB() {
      return new ReactiveJwtAuthenticationConverter();
    }
  }

  @Configuration
  static class TwoIntrospectionConvertersOnePrimary {
    @Bean
    @Primary
    ReactiveOpaqueTokenAuthenticationConverter converterA() {
      return mock(ReactiveOpaqueTokenAuthenticationConverter.class);
    }

    @Bean
    ReactiveOpaqueTokenAuthenticationConverter converterB() {
      return mock(ReactiveOpaqueTokenAuthenticationConverter.class);
    }
  }

  @Configuration
  static class TwoIntrospectionConvertersOneWithDefaultName {
    @Bean
    ReactiveOpaqueTokenAuthenticationConverter converterA() {
      return mock(ReactiveOpaqueTokenAuthenticationConverter.class);
    }

    @Bean
    ReactiveOpaqueTokenAuthenticationConverter introspectionAuthenticationConverter() {
      return mock(ReactiveOpaqueTokenAuthenticationConverter.class);
    }
  }

  @Configuration
  static class TwoIntrospectionConvertersWithoutPreference {
    @Bean
    ReactiveOpaqueTokenAuthenticationConverter converterA() {
      return mock(ReactiveOpaqueTokenAuthenticationConverter.class);
    }

    @Bean
    ReactiveOpaqueTokenAuthenticationConverter converterB() {
      return mock(ReactiveOpaqueTokenAuthenticationConverter.class);
    }
  }
}
