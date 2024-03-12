package com.c4soft;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4soft.DemoController.Dto;
import com.jayway.jsonpath.JsonPath;

import net.minidev.json.JSONArray;

@SpringBootTest
@AutoConfigureWebTestClient
class EnumBugReproducerApplicationTests {
	@Autowired
	WebTestClient api;

	JsonPath namePath = JsonPath.compile("$.name");
	JsonPath strPath = JsonPath.compile("$.str");
	JsonPath bijPath = JsonPath.compile("$.bij");

	JsonPath namePossibleValuesPath = JsonPath.compile("$.components.schemas.Dto.properties.name.enum.*");
	JsonPath strPossibleValuesPath = JsonPath.compile("$.components.schemas.Dto.properties.str.enum.*");
	JsonPath bijPossibleValuesPath = JsonPath.compile("$.components.schemas.Dto.properties.bij.enum.*");

	JsonPath nameRequestParamPossibleValuesPath = JsonPath.compile("$.paths./demo.get.parameters[?(@.name==\"nameRequestParam\")].schema.enum.*");
	JsonPath strRequestParamPossibleValuesPath = JsonPath.compile("$.paths./demo.get.parameters[?(@.name==\"strRequestParam\")].schema.enum.*");
	JsonPath bijRequestParamPossibleValuesPath = JsonPath.compile("$.paths./demo.get.parameters[?(@.name==\"bijRequestParam\")].schema.enum.*");

	// @Test
	void whenUsingNameUnlessToStringIsDecoratedWithJsonValue_thenOk() throws Exception {
		final var spec = api.get().uri("/v3/api-docs").exchange().returnResult(String.class).getResponseBody().blockFirst();
		final var nameRequestParamPossibleValues = (JSONArray) nameRequestParamPossibleValuesPath.read(spec);
		final var strRequestParamPossibleValues = (JSONArray) strRequestParamPossibleValuesPath.read(spec);
		final var bijRequestParamPossibleValues = (JSONArray) bijRequestParamPossibleValuesPath.read(spec);
		final var namePossibleValues = (JSONArray) namePossibleValuesPath.read(spec);
		final var strPossibleValues = (JSONArray) strPossibleValuesPath.read(spec);
		final var bijPossibleValues = (JSONArray) bijPossibleValuesPath.read(spec);

		for (var name : nameRequestParamPossibleValues) {
			for (var str : strRequestParamPossibleValues) {
				for (var bij : bijRequestParamPossibleValues) {
					final var actual = api.get()
							.uri(
									uri -> uri.path("/demo").queryParam("nameRequestParam", (String) name).queryParam("strRequestParam", (String) str)
											.queryParam("bijRequestParam", (String) bij).build())
							.exchange().expectStatus().isOk().returnResult(Dto.class).getResponseBody().blockFirst();

					assertTrue(strPossibleValues.contains(actual.str()));
					assertTrue(namePossibleValues.contains(actual.name()));
					assertTrue(bijPossibleValues.contains(actual.bij()));
				}
			}
		}
	}

	// @Test
	void givenEnumValuesAreTakenFromSchema_whenDeserializedAsRequestBody_thenOk() throws Exception {
		final var spec = api.get().uri("/v3/api-docs").exchange().returnResult(String.class).getResponseBody().blockFirst();
		final var namePossibleValues = (JSONArray) namePossibleValuesPath.read(spec);
		final var strPossibleValues = (JSONArray) strPossibleValuesPath.read(spec);
		final var bijPossibleValues = (JSONArray) bijPossibleValuesPath.read(spec);

		for (var name : namePossibleValues) {
			for (var str : strPossibleValues) {
				for (var bij : bijPossibleValues) {
					api.put().uri("/demo").contentType(MediaType.APPLICATION_JSON)
							.bodyValue("{ \"name\": \"%s\", \"str\": \"%s\", \"bij\": \"%s\" }".formatted(name, str, bij)).exchange().expectStatus()
							.isAccepted();
				}
			}
		}
	}

}
