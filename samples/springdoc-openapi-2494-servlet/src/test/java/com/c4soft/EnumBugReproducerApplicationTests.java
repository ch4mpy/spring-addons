package com.c4soft;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;

import net.minidev.json.JSONArray;

@SpringBootTest
@AutoConfigureMockMvc
class EnumBugReproducerApplicationTests {
	@Autowired
	MockMvc mockMvc;

	JsonPath namePath = JsonPath.compile("$.name");
	JsonPath strPath = JsonPath.compile("$.str");
	JsonPath bijPath = JsonPath.compile("$.bij");

	JsonPath namePossibleValuesPath = JsonPath.compile("$.components.schemas.Dto.properties.name.enum.*");
	JsonPath strPossibleValuesPath = JsonPath.compile("$.components.schemas.Dto.properties.str.enum.*");
	JsonPath bijPossibleValuesPath = JsonPath.compile("$.components.schemas.Dto.properties.bij.enum.*");

	JsonPath nameRequestParamPossibleValuesPath = JsonPath.compile("$.paths./demo.get.parameters[?(@.name==\"nameRequestParam\")].schema.enum.*");
	JsonPath strRequestParamPossibleValuesPath = JsonPath.compile("$.paths./demo.get.parameters[?(@.name==\"strRequestParam\")].schema.enum.*");
	JsonPath bijRequestParamPossibleValuesPath = JsonPath.compile("$.paths./demo.get.parameters[?(@.name==\"bijRequestParam\")].schema.enum.*");

	@Test
	void whenUsingNameUnlessToStringIsDecoratedWithJsonValue_thenOk() throws Exception {
		final var spec = mockMvc.perform(get("/v3/api-docs")).andReturn().getResponse().getContentAsString();
		final var nameRequestParamPossibleValues = (JSONArray) nameRequestParamPossibleValuesPath.read(spec);
		final var strRequestParamPossibleValues = (JSONArray) strRequestParamPossibleValuesPath.read(spec);
		final var bijRequestParamPossibleValues = (JSONArray) bijRequestParamPossibleValuesPath.read(spec);
		final var namePossibleValues = (JSONArray) namePossibleValuesPath.read(spec);
		final var strPossibleValues = (JSONArray) strPossibleValuesPath.read(spec);
		final var bijPossibleValues = (JSONArray) bijPossibleValuesPath.read(spec);

		for (var name : nameRequestParamPossibleValues) {
			for (var str : strRequestParamPossibleValues) {
				for (var bij : bijRequestParamPossibleValues) {
					final var actual = mockMvc
							.perform(
									get("/demo")
											.param("nameRequestParam", (String) name)
											.param("strRequestParam", (String) str)
											.param("bijRequestParam", (String) bij))
							.andExpect(status().isOk())
							.andReturn()
							.getResponse()
							.getContentAsString();

					final var actualEnumSerializedByName = namePath.read(actual);
					final var actualEnumSerializedByToString = strPath.read(actual);
					final var actualBijectiveEnumSerializedByToString = bijPath.read(actual);

					assertTrue(strPossibleValues.contains(actualEnumSerializedByToString));
					assertTrue(namePossibleValues.contains(actualEnumSerializedByName));
					assertTrue(bijPossibleValues.contains(actualBijectiveEnumSerializedByToString));
				}
			}
		}
	}

	@Test
	void givenEnumValuesAreTakenFromSchema_whenDeserializedAsRequestParam_thenOk() throws Exception {
		final var spec = mockMvc.perform(get("/v3/api-docs")).andReturn().getResponse().getContentAsString();
		final var nameRequestParamPossibleValues = (JSONArray) nameRequestParamPossibleValuesPath.read(spec);
		final var strRequestParamPossibleValues = (JSONArray) strRequestParamPossibleValuesPath.read(spec);
		final var bijRequestParamPossibleValues = (JSONArray) bijRequestParamPossibleValuesPath.read(spec);

		for (var name : nameRequestParamPossibleValues) {
			for (var str : strRequestParamPossibleValues) {
				for (var bij : bijRequestParamPossibleValues) {
					mockMvc
							.perform(
									get("/demo")
											.param("nameRequestParam", (String) name)
											.param("strRequestParam", (String) str)
											.param("bijRequestParam", (String) bij))
							.andExpect(status().isOk());
				}
			}
		}
	}

	@Test
	void givenEnumValuesAreTakenFromSchema_whenDeserializedAsRequestBody_thenOk() throws Exception {
		final var spec = mockMvc.perform(get("/v3/api-docs")).andReturn().getResponse().getContentAsString();
		final var namePossibleValues = (JSONArray) namePossibleValuesPath.read(spec);
		final var strPossibleValues = (JSONArray) strPossibleValuesPath.read(spec);
		final var bijPossibleValues = (JSONArray) bijPossibleValuesPath.read(spec);

		for (var name : namePossibleValues) {
			for (var str : strPossibleValues) {
				for (var bij : bijPossibleValues) {
					mockMvc
							.perform(
									put("/demo")
											.contentType(MediaType.APPLICATION_JSON)
											.content("{ \"name\": \"%s\", \"str\": \"%s\", \"bij\": \"%s\" }".formatted(name, str, bij)))
							.andExpect(status().isAccepted());
				}
			}
		}
	}

}
