package com.c4_soft.springaddons.security.oidc;

import org.jspecify.annotations.Nullable;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import com.jayway.jsonpath.internal.function.PathFunctionFactory;

/**
 * Registers, for native images, the constructors of the JsonPath functions ({@code length()},
 * {@code keys()}, ...) which JsonPath creates by reflection when a path such as those of
 * {@link ClaimSet#getByJsonPath(String)} or of the authorities mapping uses them.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class JsonPathFunctionsRuntimeHints implements RuntimeHintsRegistrar {

  @Override
  public void registerHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
    PathFunctionFactory.FUNCTIONS.values().forEach(function -> hints.reflection()
        .registerType(function, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS));
  }
}
