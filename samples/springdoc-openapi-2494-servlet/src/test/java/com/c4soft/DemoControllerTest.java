package com.c4soft;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.c4soft.DemoController.BijectiveEnumSerializedByToString;
import com.c4soft.DemoController.EnumSerializedByName;
import com.c4soft.DemoController.EnumSerializedByToString;
import com.fasterxml.jackson.databind.ObjectMapper;

@WebMvcTest(controllers = DemoController.class)
class DemoControllerTest {

	@Autowired
	MockMvc mockMvc;

	ObjectMapper om = new ObjectMapper();

	@Test
	void whenUsingNameUnlessEnumHasCustomConverter_thenOk() throws Exception {
		mockMvc
				.perform(
						get("/demo")
								.param("nameRequestParam", EnumSerializedByName.A.name())
								.param("strRequestParam", EnumSerializedByToString.A.name())
								.param("bijRequestParam", BijectiveEnumSerializedByToString.A.toString()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("name", is(EnumSerializedByName.A.name())))
				.andExpect(jsonPath("str", is(EnumSerializedByToString.A.toString())))
				.andExpect(jsonPath("bij", is(BijectiveEnumSerializedByToString.A.toString())));
	}

	@Test
	void whenUsingToStringOutputOnEnumWithDefaultRequestParamConverter_thenKo() throws Exception {
		mockMvc
				.perform(
						get("/demo")
								.param("nameRequestParam", EnumSerializedByName.A.toString())
								.param("strRequestParam", EnumSerializedByToString.A.name())
								.param("bijRequestParam", BijectiveEnumSerializedByToString.A.toString()))
				.andExpect(status().is4xxClientError());

		mockMvc
				.perform(
						get("/demo")
								.param("nameRequestParam", EnumSerializedByName.A.name())
								.param("strRequestParam", EnumSerializedByToString.A.toString())
								.param("bijRequestParam", BijectiveEnumSerializedByToString.A.toString()))
				.andExpect(status().is4xxClientError());
	}

	@Test
	void whenUsingNameOnEnumWithCustomConverter_thenKo() throws Exception {
		mockMvc
				.perform(
						get("/demo")
								.param("nameRequestParam", EnumSerializedByName.A.name())
								.param("strRequestParam", EnumSerializedByToString.A.name())
								.param("bijRequestParam", BijectiveEnumSerializedByToString.A.name()))
				.andExpect(status().is4xxClientError());
	}

	@Test
	void whenUsingNameUnlessToStringIsJsonValue_thenOk() throws Exception {
		mockMvc
				.perform(put("/demo").contentType(MediaType.APPLICATION_JSON_VALUE).content("{\"name\":\"A\",\"str\":\"str a\",\"bij\":\"bij a\"}"))
				.andExpect(status().isAccepted());
	}

	@Test
	void whenUsingNameAndToStringIsJsonValue_thenKo() throws Exception {
		mockMvc
				.perform(put("/demo").contentType(MediaType.APPLICATION_JSON_VALUE).content("{\"name\":\"A\",\"str\":\"A\",\"bij\":\"bij a\"}"))
				.andExpect(status().is4xxClientError());

		mockMvc
				.perform(put("/demo").contentType(MediaType.APPLICATION_JSON_VALUE).content("{\"name\":\"A\",\"str\":\"str a\",\"bij\":\"A\"}"))
				.andExpect(status().is4xxClientError());
	}

}
