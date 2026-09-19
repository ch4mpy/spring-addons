package com.c4_soft.springaddons.openapi;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import com.jayway.jsonpath.JsonPath;

/**
 * What the generated spec must contain for {@link EnumsApplication}, whatever the stack.
 */
final class OpenApiEnumValuesAssertions {

  private OpenApiEnumValuesAssertions() {}

  static List<String> bodyValues(String spec, String property) {
    return JsonPath.read(spec, "$.components.schemas.Dto.properties.%s.enum".formatted(property));
  }

  static List<String> parameterValues(String spec, String parameter) {
    final List<List<String>> values = JsonPath.read(spec,
        "$.paths./demo/{pathEnum}.get.parameters[?(@.name=='%s')].schema.enum".formatted(parameter));
    assertThat(values).as("schema of parameter %s", parameter).hasSize(1);
    return values.get(0);
  }

  /**
   * Bodies are (de)serialized by Jackson 2, which uses name() by default (and @JsonValue when
   * present); parameters go through the conversion service: name() unless a converter is
   * registered.
   */
  static void assertSpec(String spec) {
    assertThat(bodyValues(spec, "name")).containsExactly("A", "B");
    assertThat(bodyValues(spec, "str")).containsExactly("str a", "str b");
    assertThat(bodyValues(spec, "bij")).containsExactly("bij a", "bij b");

    assertThat(parameterValues(spec, "pathEnum")).containsExactly("A", "B");
    assertThat(parameterValues(spec, "nameRequestParam")).containsExactly("A", "B");
    assertThat(parameterValues(spec, "strRequestParam")).containsExactly("A", "B");
    assertThat(parameterValues(spec, "bijRequestParam")).containsExactly("bij a", "bij b");
    assertThat(parameterValues(spec, "X-Enum")).containsExactly("A", "B");
  }
}
