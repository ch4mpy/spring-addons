package com.c4_soft.springaddons.openapi;

import java.util.Objects;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Reproducer for <a href="https://github.com/springdoc/springdoc-openapi/issues/2494">springdoc
 * #2494</a>: the same controller works in a servlet and in a reactive application.
 */
@SpringBootApplication
public class EnumsApplication {

  public static void main(String[] args) {
    SpringApplication.run(EnumsApplication.class, args);
  }

  @RestController
  public static class DemoController {

    @GetMapping("/demo/{pathEnum}")
    public Dto getDemo(@PathVariable ByName pathEnum, @RequestParam ByName nameRequestParam,
        @RequestParam ByToString strRequestParam,
        @RequestParam WithConverter bijRequestParam,
        @RequestHeader(name = "X-Enum", required = false) ByToString headerEnum) {
      return new Dto(nameRequestParam, strRequestParam, bijRequestParam);
    }

    @PutMapping("/demo")
    public ResponseEntity<Void> putDemo(@RequestBody Dto dto) {
      return ResponseEntity.accepted().build();
    }
  }

  public record Dto(ByName name, ByToString str, WithConverter bij) {
  }

  /**
   * A custom toString(), but no @JsonValue nor Converter&lt;String, E&gt;: Jackson 2 writes and
   * reads it with name() (default {@code EnumFeature}s), and so does the conversion service
   */
  public enum ByName {
    A("name a"), B("name b");

    private final String label;

    ByName(String label) {
      this.label = label;
    }

    @Override
    public String toString() {
      return label;
    }
  }

  /**
   * @JsonValue on toString(), but no Converter&lt;String, E&gt;: JSON uses the labels, the
   * conversion service still expects name()
   */
  public enum ByToString {
    A("str a"), B("str b");

    private final String label;

    ByToString(String label) {
      this.label = label;
    }

    @Override
    @JsonValue
    public String toString() {
      return label;
    }
  }

  /**
   * @JsonValue on toString() and a Converter&lt;String, E&gt; reading it back: labels everywhere
   */
  public enum WithConverter {
    A("bij a"), B("bij b");

    private final String label;

    WithConverter(String label) {
      this.label = label;
    }

    @Override
    @JsonValue
    public String toString() {
      return label;
    }

    @Component
    static class StringToWithConverter implements Converter<String, WithConverter> {
      @Override
      public WithConverter convert(String source) {
        for (final var e : WithConverter.values()) {
          if (Objects.equals(e.toString(), source)) {
            return e;
          }
        }
        return null;
      }
    }
  }
}
