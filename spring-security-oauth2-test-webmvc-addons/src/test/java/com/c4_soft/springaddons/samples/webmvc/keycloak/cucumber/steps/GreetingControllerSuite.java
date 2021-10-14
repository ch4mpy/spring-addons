package com.c4_soft.springaddons.samples.webmvc.keycloak.cucumber.steps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import java.util.List;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak.ServletKeycloakAuthUnitTestingSupport;

import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

public class GreetingControllerSuite {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	ServletKeycloakAuthUnitTestingSupport keycloak;

	MvcResult result;

	@Given("user is not authenticated")
	public void unauthenticatedUser() {
		TestSecurityContextHolder.clearContext();
	}

	@Given("the following user roles:")
	public void authenticateAsUser(List<String> rolesTable) {
		TestSecurityContextHolder.clearContext();
		final Stream<String> roles = rolesTable.stream().map(String::trim);
		TestSecurityContextHolder.setAuthentication(keycloak.authentication().authorities(roles).build());
	}

	@When("a get request is sent to greeting endpoint")
	public void getGreet() throws Exception {
		result = mockMvc.perform(get("/greet")).andReturn();
	}

	@Then("user is redirected to login")
	public void redirectedToLogin() throws Exception {
		assertEquals(302, result.getResponse().getStatus());
	}

	@Then("a greeting is returned")
	public void greetingIsReturned() throws Exception {
		assertEquals(200, result.getResponse().getStatus());
		final var body = result.getResponse().getContentAsString();
		assertThat(body.contains("Hello user! You are granted with "));
		assertThat(body.contains("ROLE_user"));
		assertThat(body.contains("ROLE_TESTER"));
	}

}
