package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import static org.assertj.core.api.Assertions.assertThat;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ReactiveSpringAddonsOidcBeans;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ReactiveJwtAbstractAuthenticationTokenConverter;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ReactiveSpringAddonsOidcResourceServerBeans;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.SpringAddonsOidcBeans;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JwtAbstractAuthenticationTokenConverter;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.SpringAddonsOidcResourceServerBeans;

/**
 * Which authorities converter the default authentication converters run: the default
 * {@code authoritiesConverter} backs off for any
 * {@code Converter<Map<String, Object>, Collection<? extends GrantedAuthority>>} bean whatever its
 * name (it used to back off only for a {@code ClaimSetAuthoritiesConverter}, and the by-type
 * injection then silently fell back on the default, ignoring the application's bean), and with
 * several such beans the {@code @Primary} one or the one named like the default wins.
 */
class AuthoritiesConverterSelectionTest {
  private static final String ISSUER = "https://localhost:8443/realms/test";
  private static final String DEFAULT_BEAN_NAME = "authoritiesConverter";

  private final WebApplicationContextRunner servletRunner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, SpringAddonsOidcProperties.class,
          SpringAddonsOidcBeans.class, SpringAddonsOidcResourceServerBeans.class,
          ServerProperties.class))
      .withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].iss=" + ISSUER);

  private final ReactiveWebApplicationContextRunner reactiveRunner =
      new ReactiveWebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, SpringAddonsOidcProperties.class,
              ReactiveSpringAddonsOidcBeans.class,
              ReactiveSpringAddonsOidcResourceServerBeans.class, ServerProperties.class))
          .withPropertyValues("com.c4-soft.springaddons.oidc.ops[0].iss=" + ISSUER);

  static Jwt jwt() {
    return new Jwt("test.jwt.bearer", Instant.now(), Instant.now().plusSeconds(42),
        Map.of("alg", "none"), Map.of("iss", ISSUER, "sub", "42"));
  }

  static List<String> servletAuthorities(ApplicationContext context) {
    return context.getBean(JwtAbstractAuthenticationTokenConverter.class).convert(jwt())
        .getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
  }

  static List<String> reactiveAuthorities(ApplicationContext context) {
    return context.getBean(ReactiveJwtAbstractAuthenticationTokenConverter.class).convert(jwt())
        .block().getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
  }

  @Test
  void givenNoConverterBean_thenDefaultIsCreated() {
    servletRunner.run(context -> assertThat(context).hasBean(DEFAULT_BEAN_NAME));
    reactiveRunner.run(context -> assertThat(context).hasBean(DEFAULT_BEAN_NAME));
  }

  @Test
  void givenConverterBeanWithAnotherName_thenDefaultBacksOffAndTheBeanIsUsed() {
    servletRunner.withUserConfiguration(SingleConverterWithAnotherName.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).doesNotHaveBean(DEFAULT_BEAN_NAME);
      assertThat(servletAuthorities(context)).containsExactly("ANOTHER_NAME");
    });
    reactiveRunner.withUserConfiguration(SingleConverterWithAnotherName.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context).doesNotHaveBean(DEFAULT_BEAN_NAME);
      assertThat(reactiveAuthorities(context)).containsExactly("ANOTHER_NAME");
    });
  }

  @Test
  void givenTwoConverterBeansOnePrimary_thenPrimaryIsUsed() {
    servletRunner.withUserConfiguration(TwoConvertersOnePrimary.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(servletAuthorities(context)).containsExactly("PRIMARY");
    });
    reactiveRunner.withUserConfiguration(TwoConvertersOnePrimary.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(reactiveAuthorities(context)).containsExactly("PRIMARY");
    });
  }

  @Test
  void givenTwoConverterBeansOneWithDefaultName_thenItIsUsed() {
    servletRunner.withUserConfiguration(TwoConvertersOneWithDefaultName.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(servletAuthorities(context)).containsExactly("DEFAULT_NAME");
    });
    reactiveRunner.withUserConfiguration(TwoConvertersOneWithDefaultName.class).run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(reactiveAuthorities(context)).containsExactly("DEFAULT_NAME");
    });
  }

  @Test
  void givenTwoConverterBeansWithoutPreference_thenContextFails() {
    servletRunner.withUserConfiguration(TwoConvertersWithoutPreference.class)
        .run(context -> assertThat(context).getFailure()
            .hasRootCauseInstanceOf(NoUniqueBeanDefinitionException.class));
    reactiveRunner.withUserConfiguration(TwoConvertersWithoutPreference.class)
        .run(context -> assertThat(context).getFailure()
            .hasRootCauseInstanceOf(NoUniqueBeanDefinitionException.class));
  }

  static Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> converter(
      String marker) {
    return claims -> List.of(new SimpleGrantedAuthority(marker));
  }

  @Configuration
  static class SingleConverterWithAnotherName {
    @Bean
    Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> myAuthoritiesConverter() {
      return converter("ANOTHER_NAME");
    }
  }

  @Configuration
  static class TwoConvertersOnePrimary {
    @Bean
    @Primary
    Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> converterA() {
      return converter("PRIMARY");
    }

    @Bean
    Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> converterB() {
      return converter("CONVERTER_B");
    }
  }

  @Configuration
  static class TwoConvertersOneWithDefaultName {
    @Bean
    Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> converterA() {
      return converter("CONVERTER_A");
    }

    @Bean
    Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter() {
      return converter("DEFAULT_NAME");
    }
  }

  @Configuration
  static class TwoConvertersWithoutPreference {
    @Bean
    Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> converterA() {
      return converter("CONVERTER_A");
    }

    @Bean
    Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> converterB() {
      return converter("CONVERTER_B");
    }
  }
}
