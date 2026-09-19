package com.c4_soft.springaddons.openapi;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(classes = EnumsApplication.class,
    properties = "spring.main.web-application-type=reactive")
@AutoConfigureWebTestClient
class ReactiveEnumValuesTest {
  @Autowired
  WebTestClient api;

  @Test
  void whenGetApiDocs_thenEnumValuesAreThoseSpringAcceptsAndEmits() {
    OpenApiEnumValuesAssertions.assertSpec(spec());
  }

  @Test
  void givenParameterValuesFromSpec_whenGet_thenAccepted() {
    final var spec = spec();
    for (var path : OpenApiEnumValuesAssertions.parameterValues(spec, "pathEnum")) {
      for (var name : OpenApiEnumValuesAssertions.parameterValues(spec, "nameRequestParam")) {
        for (var str : OpenApiEnumValuesAssertions.parameterValues(spec, "strRequestParam")) {
          for (var bij : OpenApiEnumValuesAssertions.parameterValues(spec, "bijRequestParam")) {
            for (var header : OpenApiEnumValuesAssertions.parameterValues(spec, "X-Enum")) {
              api.get()
                  .uri(uri -> uri.path("/demo/{pathEnum}").queryParam("nameRequestParam", name)
                      .queryParam("strRequestParam", str).queryParam("bijRequestParam", bij)
                      .build(path))
                  .header("X-Enum", header).exchange().expectStatus().isOk();
            }
          }
        }
      }
    }
  }

  @Test
  void givenBodyValuesFromSpec_whenPut_thenAccepted() {
    final var spec = spec();
    for (var name : OpenApiEnumValuesAssertions.bodyValues(spec, "name")) {
      for (var str : OpenApiEnumValuesAssertions.bodyValues(spec, "str")) {
        for (var bij : OpenApiEnumValuesAssertions.bodyValues(spec, "bij")) {
          api.put().uri("/demo").contentType(MediaType.APPLICATION_JSON)
              .bodyValue("{ \"name\": \"%s\", \"str\": \"%s\", \"bij\": \"%s\" }".formatted(name,
                  str, bij))
              .exchange().expectStatus().isAccepted();
        }
      }
    }
  }

  private String spec() {
    return api.get().uri("/v3/api-docs").exchange().expectStatus().isOk()
        .expectBody(String.class).returnResult().getResponseBody();
  }
}
