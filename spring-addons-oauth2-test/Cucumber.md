# Unit-testing a secured Spring `@Component` with Cucumber

Do this only if you are forced to. In my opinion, JUnit is better for unit-tests (and is better tooled for Spring)

If you have no choice, first thing to know is that annotations like `@WithMockUser` and `@WithMockKeyckloakAuth` won't work.
The reason is Cucumber does not support spring `WithSecurityContextTestExecutionListener` around scenarios (`TestExecutionListener` are executed before and after JUnit tests). And [they don't want to](https://github.com/cucumber/cucumber-jvm/issues/2408).

As a consequence, test security context setup must be done manually in `@Given` steps. The only help this lib can bring is with the `Authentication` builders it exposes:
- `KeycloakAuthenticationTokenTestingBuilder<T extends KeycloakAuthenticationTokenTestingBuilder<T>>`
- `OpenidClaimSetBuilder`
- `OAuthenticationTestingBuilder<T extends OAuthenticationTestingBuilder<T>>`

## Minimal sample from [gh-29](https://github.com/ch4mpy/spring-addons/issues/29)

As I'm making use of `ServletKeycloakAuthUnitTestingSupport` to get a `KeycloakAuthRequestPostProcessor` instance (because it's a `KeycloakAuthenticationTokenTestingBuilder<KeycloakAuthRequestPostProcessor>`), a dependency on `spring-addons-webmvc-test` is required in addition to `cucumber-java`, `cucumber-junit` and `cucumber-spring`.

Gherkin feature:
```
Feature: Testing a secured REST API
  Users should be able to GET greetings only if authenticated

  Scenario: Authorized users should be greeted
    Given the following user roles:
      | ROLE_user   |
      | ROLE_TESTER |
    When a get request is sent to greeting endpoint
    Then a greeting is returned

  Scenario: Unauthorized users shouldn't be able to access greetings
    Given user is not authenticated
    When a get request is sent to greeting endpoint
    Then user is redirected to login
```

Step definitions:
``` java
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
```

Cucumber JUnit 4 adapter:
``` java
package com.c4_soft.springaddons.samples.webmvc.keycloak.cucumber;

import org.junit.runner.RunWith;

import io.cucumber.junit.Cucumber;
import io.cucumber.junit.CucumberOptions;

@RunWith(Cucumber.class)
@CucumberOptions(features = "classpath:cucumber-features", plugin = {
		"pretty",
		"html:target/cucumber" }, extraGlue = "com.c4_soft.springaddons.samples.webmvc.keycloak.cucumber.extraglue")
public class CucumberIntegrationTest {
}
```

Spring "extraglue":
``` java
package com.c4_soft.springaddons.samples.webmvc.keycloak.cucumber.extraglue;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;

import com.c4_soft.springaddons.samples.webmvc.keycloak.KeycloakSpringBootSampleApp;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.keycloak.ServletKeycloakAuthUnitTestingSupport;

import io.cucumber.spring.CucumberContextConfiguration;

@CucumberContextConfiguration
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@ContextConfiguration(classes = { KeycloakSpringBootSampleApp.class, ServletKeycloakAuthUnitTestingSupport.class })
@AutoConfigureMockMvc
public class CucumberSpringConfiguration {
}
```
