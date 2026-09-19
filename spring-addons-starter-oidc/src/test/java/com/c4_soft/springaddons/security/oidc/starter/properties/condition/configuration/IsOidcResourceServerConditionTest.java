package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.security.oauth2.server.resource.web.HeaderBearerTokenResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.SpringAddonsOidcResourceServerBeans;

/**
 * Asserts when the resource server auto-configuration is evaluated, using one of the beans it
 * always defines when active as a witness.
 */
class IsOidcResourceServerConditionTest {

  private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringAddonsOidcProperties.class,
          SpringAddonsOidcResourceServerBeans.class, ServerProperties.class))
      .withPropertyValues(
          "com.c4-soft.springaddons.oidc.ops[0].iss=https://localhost:8443/realms/test");

  @Test
  void givenResourceServerIsOnClassPath_thenAutoConfigurationIsApplied() {
    contextRunner.run(context -> assertThat(context)
        .hasSingleBean(ResourceServerExpressionInterceptUrlRegistryPostProcessor.class));
  }

  @Test
  void givenResourceServerIsDisabled_thenAutoConfigurationBacksOff() {
    contextRunner.withPropertyValues("com.c4-soft.springaddons.oidc.resourceserver.enabled=false")
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context)
              .doesNotHaveBean(ResourceServerExpressionInterceptUrlRegistryPostProcessor.class);
        });
  }

  /**
   * The auto-configuration references Spring Boot's {@link OAuth2ResourceServerProperties} in a bean
   * signature, so having only the Spring Security jar (pulled transitively, for instance by
   * spring-addons-starter-oidc-test in an OAuth2 client application) must not be enough for it to be
   * evaluated: the context used to fail with a {@code NoClassDefFoundError}.
   */
  @Test
  void givenOnlySpringSecurityResourceServerIsOnClassPath_thenContextStartsWithoutResourceServer() {
    contextRunner.withClassLoader(new FilteredClassLoader(OAuth2ResourceServerProperties.class))
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context)
              .doesNotHaveBean(ResourceServerExpressionInterceptUrlRegistryPostProcessor.class);
        });
  }

  @Test
  void givenNoResourceServerOnClassPath_thenAutoConfigurationBacksOff() {
    contextRunner
        .withClassLoader(new FilteredClassLoader(HeaderBearerTokenResolver.class,
            OAuth2ResourceServerProperties.class))
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context)
              .doesNotHaveBean(ResourceServerExpressionInterceptUrlRegistryPostProcessor.class);
        });
  }
}
