package com.c4_soft.springaddons.samples.webmvc.keycloak.cucumber.steps;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak.ServletKeycloakAuthUnitTestingSupport;

import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

public class GreetingControllerSuite {

	@Autowired
	MockMvc mockMvc;

	@Autowired
	ServletKeycloakAuthUnitTestingSupport keycloak;

	@When("unauthenticated users want to get greeting")
	public void unauthenticatedUsersWantToGetGreeting() throws Exception {
	}

	@Then("it is redirected to login")
	public void itIsRedirectedToLogin() throws Exception {
		mockMvc.perform(get("/greet")).andExpect(status().is3xxRedirection());
	}

	@When("authenticated users want to get greeting")
	public void authenticatedUsersWantToGetGreeting() throws Exception {
	}

	@Then("a greeting is returned")
	public void aGreetingIsReturned() throws Exception {
		mockMvc.perform(get("/greet").with(keycloak.authentication())).andExpect(status().isOk());
	}

}
