package com.c4soft;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4soft.DemoController.BijectiveEnumSerializedByToString;
import com.c4soft.DemoController.EnumSerializedByName;
import com.c4soft.DemoController.EnumSerializedByToString;
import com.fasterxml.jackson.databind.ObjectMapper;

@WebFluxTest(controllers = DemoController.class)
class DemoControllerTest {

	@Autowired
	WebTestClient api;

	ObjectMapper om = new ObjectMapper();

	@Test
	void whenUsingNameUnlessEnumHasCustomConverter_thenOk() throws Exception {
		api.get()
				.uri(
						uri -> uri.path("/demo").queryParam("nameRequestParam", EnumSerializedByName.A.name())
								.queryParam("strRequestParam", EnumSerializedByToString.A.name())
								.queryParam("bijRequestParam", BijectiveEnumSerializedByToString.A.toString()).build())
				.exchange().expectStatus().isOk().expectBody().jsonPath("name").isEqualTo(EnumSerializedByName.A.name()).jsonPath("str")
				.isEqualTo(EnumSerializedByToString.A.toString()).jsonPath("bij").isEqualTo(BijectiveEnumSerializedByToString.A.toString());
	}

	@Test
	void whenUsingToStringOutputOnEnumWithDefaultRequestParamConverter_thenKo() throws Exception {
		api.get()
				.uri(
						uri -> uri.path("/demo").queryParam("nameRequestParam", EnumSerializedByName.A.toString())
								.queryParam("strRequestParam", EnumSerializedByToString.A.name())
								.queryParam("bijRequestParam", BijectiveEnumSerializedByToString.A.toString()).build())
				.exchange().expectStatus().is4xxClientError();

		api.get()
				.uri(
						uri -> uri.path("/demo").queryParam("nameRequestParam", EnumSerializedByName.A.name())
								.queryParam("strRequestParam", EnumSerializedByToString.A.toString())
								.queryParam("bijRequestParam", BijectiveEnumSerializedByToString.A.toString()).build())
				.exchange().expectStatus().is4xxClientError();
	}

	@Test
	void whenUsingNameOnEnumWithCustomConverter_thenKo() throws Exception {
		api.get()
				.uri(
						uri -> uri.path("/demo").queryParam("nameRequestParam", EnumSerializedByName.A.name())
								.queryParam("strRequestParam", EnumSerializedByToString.A.name())
								.queryParam("bijRequestParam", BijectiveEnumSerializedByToString.A.name()).build())
				.exchange().expectStatus().is4xxClientError();
	}

	@Test
	void whenUsingNameUnlessToStringIsJsonValue_thenOk() throws Exception {
		api.put().uri(uri -> uri.path("/demo").build()).contentType(MediaType.APPLICATION_JSON)
				.bodyValue("{\"name\":\"A\",\"str\":\"str a\",\"bij\":\"bij a\"}").exchange().expectStatus().isAccepted();
	}

	@Test
	void whenUsingNameAndToStringIsJsonValue_thenKo() throws Exception {
		api.put().uri(uri -> uri.path("/demo").build()).contentType(MediaType.APPLICATION_JSON).bodyValue("{\"name\":\"A\",\"str\":\"A\",\"bij\":\"bij a\"}")
				.exchange().expectStatus().is4xxClientError();

		api.put().uri(uri -> uri.path("/demo").build()).contentType(MediaType.APPLICATION_JSON).bodyValue("{\"name\":\"A\",\"str\":\"str a\",\"bij\":\"A\"}")
				.exchange().expectStatus().is4xxClientError();
	}

}
