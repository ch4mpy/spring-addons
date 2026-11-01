package com.c4_soft.springaddons.security.oidc.spring;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;
import org.springframework.beans.factory.aot.AotServices;

/**
 * SpEL calls the methods of the expression root by reflection: they must be registered for native
 * images, by a registrar Spring AOT finds without any configuration (gh-347).
 */
class SpringAddonsMethodSecurityExpressionRootRuntimeHintsTest {

  @Test
  void givenAotServices_whenLoadRuntimeHintsRegistrars_thenExpressionRootRegistrarIsFound() {
    assertThat(AotServices.factories().load(RuntimeHintsRegistrar.class))
        .hasAtLeastOneElementOfType(SpringAddonsMethodSecurityExpressionRootRuntimeHints.class);
  }

  @Test
  void givenRegistrar_whenRegisterHints_thenExpressionRootAccessorsCanBeInvoked() {
    final var hints = new RuntimeHints();
    new SpringAddonsMethodSecurityExpressionRootRuntimeHints().registerHints(hints,
        getClass().getClassLoader());

    for (final var accessor : new String[] {"getThis", "getReturnObject", "getFilterObject"}) {
      assertThat(hints).matches(RuntimeHintsPredicates.reflection()
          .onMethodInvocation(SpringAddonsMethodSecurityExpressionRoot.class, accessor));
    }
  }
}
