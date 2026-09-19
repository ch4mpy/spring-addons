package com.c4_soft.springaddons.openapi;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(classes = EnumsApplication.class,
    properties = "spring.main.web-application-type=servlet")
@AutoConfigureMockMvc
class ServletEnumValuesTest {
  @Autowired
  MockMvc mockMvc;

  @Test
  void whenGetApiDocs_thenEnumValuesAreThoseSpringAcceptsAndEmits() throws Exception {
    OpenApiEnumValuesAssertions.assertSpec(spec());
  }

  @Test
  void givenParameterValuesFromSpec_whenGet_thenAccepted() throws Exception {
    final var spec = spec();
    for (var path : OpenApiEnumValuesAssertions.parameterValues(spec, "pathEnum")) {
      for (var name : OpenApiEnumValuesAssertions.parameterValues(spec, "nameRequestParam")) {
        for (var str : OpenApiEnumValuesAssertions.parameterValues(spec, "strRequestParam")) {
          for (var bij : OpenApiEnumValuesAssertions.parameterValues(spec, "bijRequestParam")) {
            for (var header : OpenApiEnumValuesAssertions.parameterValues(spec, "X-Enum")) {
              mockMvc.perform(get("/demo/{pathEnum}", path).param("nameRequestParam", name)
                  .param("strRequestParam", str).param("bijRequestParam", bij)
                  .header("X-Enum", header)).andExpect(status().isOk());
            }
          }
        }
      }
    }
  }

  @Test
  void givenBodyValuesFromSpec_whenPut_thenAccepted() throws Exception {
    final var spec = spec();
    for (var name : OpenApiEnumValuesAssertions.bodyValues(spec, "name")) {
      for (var str : OpenApiEnumValuesAssertions.bodyValues(spec, "str")) {
        for (var bij : OpenApiEnumValuesAssertions.bodyValues(spec, "bij")) {
          mockMvc.perform(put("/demo").contentType(MediaType.APPLICATION_JSON).content(
              "{ \"name\": \"%s\", \"str\": \"%s\", \"bij\": \"%s\" }".formatted(name, str, bij)))
              .andExpect(status().isAccepted());
        }
      }
    }
  }

  private String spec() throws Exception {
    return mockMvc.perform(get("/v3/api-docs")).andExpect(status().isOk()).andReturn()
        .getResponse().getContentAsString();
  }
}
