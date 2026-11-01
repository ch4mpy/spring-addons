package com.c4_soft.springaddons.security.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;
import org.springframework.beans.factory.aot.AotServices;
import com.jayway.jsonpath.internal.function.PathFunctionFactory;
import com.jayway.jsonpath.internal.function.json.KeySetFunction;

/**
 * JsonPath creates its functions by reflection: their constructors must be registered for native
 * images, by a registrar Spring AOT finds without any configuration (gh-346).
 */
class JsonPathFunctionsRuntimeHintsTest {

  @Test
  void givenAotServices_whenLoadRuntimeHintsRegistrars_thenJsonPathFunctionsRegistrarIsFound() {
    assertThat(AotServices.factories().load(RuntimeHintsRegistrar.class))
        .hasAtLeastOneElementOfType(JsonPathFunctionsRuntimeHints.class);
  }

  @Test
  void givenRegistrar_whenRegisterHints_thenEveryJsonPathFunctionCanBeInstantiated() throws Exception {
    final var hints = new RuntimeHints();
    new JsonPathFunctionsRuntimeHints().registerHints(hints, getClass().getClassLoader());

    assertThat(PathFunctionFactory.FUNCTIONS).containsValue(KeySetFunction.class);
    for (final Class<?> function : PathFunctionFactory.FUNCTIONS.values()) {
      assertThat(hints).matches(RuntimeHintsPredicates.reflection()
          .onConstructorInvocation(function.getDeclaredConstructor()));
    }
  }
}
