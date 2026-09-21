package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.SpringAddonsOidcResourceServerBeans;

/**
 * Which authentication converter the servlet resource server auto-configuration uses (issue #181):
 * the default backs off for any bean of the right type whatever its name, and with several such
 * beans the {@code @Primary} one or the one named like the default wins.
 */
class JwtAuthenticationConverterSelectionTest {
  private static final String DEFAULT_JWT_CONVERTER = "jwtAuthenticationConverter";
  private static final String DEFAULT_INTROSPECTION_CONVERTER = "introspectionAuthenticationConverter";

  private final WebApplicationContextRunner jwtRunner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringAddonsOidcProperties.class,
          SpringAddonsOidcResourceServerBeans.class, ServerProperties.class))
      .withPropertyValues(
          "com.c4-soft.springaddons.oidc.ops[0].iss=https://localhost:8443/realms/test");

  private final WebApplicationContextRunner introspectionRunner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringAddonsOidcProperties.class,
          OAuth2ResourceServerProperties.class, SpringAddonsOidcResourceServerBeans.class,
          ServerProperties.class))
      .withBean(OpaqueTokenIntrospector.class, () -> mock(OpaqueTokenIntrospector.class))
      .withPropertyValues(
          "com.c4-soft.springaddons.oidc.ops[0].iss=https://localhost:8443/realms/test",
          "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri=https://localhost:8443/realms/test/protocol/openid-connect/token/introspect");

  @Test
  void givenNoConverterBean_thenDefaultIsCreated() {
    jwtRunner.run(context -> {
      assertThat(context).hasBean(DEFAULT_JWT_CONVERTER);
      assertThat(context).hasSingleBean(AuthenticationManagerResolver.class);
    });
  }

  @Test
  void givenJwtAuthenticationConverterBeanWithAnotherName_thenDefaultBacksOff() {
    jwtRunner.withUserConfiguration(SingleConverterWithAnotherName.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).doesNotHaveBean(DEFAULT_JWT_CONVERTER);
      assertThat(context).hasBean("defaultJwtAuthenticationConverter");
      assertThat(context).hasSingleBean(AuthenticationManagerResolver.class);
      assertThat(context).hasSingleBean(SecurityFilterChain.class);
    });
  }

  @Test
  void givenConverterBeanToAJwtAuthenticationTokenSubtype_thenDefaultBacksOff() {
    jwtRunner.withUserConfiguration(SingleConverterToSubtype.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).doesNotHaveBean(DEFAULT_JWT_CONVERTER);
      assertThat(context).hasSingleBean(AuthenticationManagerResolver.class);
    });
  }

  @Test
  void givenTwoConverterBeansOnePrimary_thenContextStarts() {
    jwtRunner.withUserConfiguration(TwoConvertersOnePrimary.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).doesNotHaveBean(DEFAULT_JWT_CONVERTER);
      assertThat(context).hasSingleBean(AuthenticationManagerResolver.class);
    });
  }

  @Test
  void givenTwoConverterBeansOneWithDefaultName_thenContextStarts() {
    jwtRunner.withUserConfiguration(TwoConvertersOneWithDefaultName.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).hasSingleBean(AuthenticationManagerResolver.class);
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
          assertThat(context).hasSingleBean(SecurityFilterChain.class);
        });
  }

  @Test
  void givenTwoIntrospectionConverterBeansOneWithDefaultName_thenContextStarts() {
    introspectionRunner.withUserConfiguration(TwoIntrospectionConvertersOneWithDefaultName.class)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).hasSingleBean(SecurityFilterChain.class);
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
    JwtAuthenticationConverter defaultJwtAuthenticationConverter() {
      return new JwtAuthenticationConverter();
    }
  }

  @Configuration
  static class SingleConverterToSubtype {
    @Bean
    Converter<Jwt, JwtAuthenticationToken> converterToSubtype() {
      return jwt -> new JwtAuthenticationToken(jwt, List.of());
    }
  }

  @Configuration
  static class TwoConvertersOnePrimary {
    @Bean
    @Primary
    JwtAuthenticationConverter converterA() {
      return new JwtAuthenticationConverter();
    }

    @Bean
    JwtAuthenticationConverter converterB() {
      return new JwtAuthenticationConverter();
    }
  }

  @Configuration
  static class TwoConvertersOneWithDefaultName {
    @Bean
    JwtAuthenticationConverter converterA() {
      return new JwtAuthenticationConverter();
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
      return new JwtAuthenticationConverter();
    }
  }

  @Configuration
  static class TwoConvertersWithoutPreference {
    @Bean
    JwtAuthenticationConverter converterA() {
      return new JwtAuthenticationConverter();
    }

    @Bean
    JwtAuthenticationConverter converterB() {
      return new JwtAuthenticationConverter();
    }
  }

  @Configuration
  static class TwoIntrospectionConvertersOnePrimary {
    @Bean
    @Primary
    OpaqueTokenAuthenticationConverter converterA() {
      return mock(OpaqueTokenAuthenticationConverter.class);
    }

    @Bean
    OpaqueTokenAuthenticationConverter converterB() {
      return mock(OpaqueTokenAuthenticationConverter.class);
    }
  }

  @Configuration
  static class TwoIntrospectionConvertersOneWithDefaultName {
    @Bean
    OpaqueTokenAuthenticationConverter converterA() {
      return mock(OpaqueTokenAuthenticationConverter.class);
    }

    @Bean
    OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter() {
      return mock(OpaqueTokenAuthenticationConverter.class);
    }
  }

  @Configuration
  static class TwoIntrospectionConvertersWithoutPreference {
    @Bean
    OpaqueTokenAuthenticationConverter converterA() {
      return mock(OpaqueTokenAuthenticationConverter.class);
    }

    @Bean
    OpaqueTokenAuthenticationConverter converterB() {
      return mock(OpaqueTokenAuthenticationConverter.class);
    }
  }
}
