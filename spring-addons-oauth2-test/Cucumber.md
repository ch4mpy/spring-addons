# Unit-testing a secured Spring `@Component` with Cucumber

Do this only if you are forced to. In my opinion, JUnit is better for unit-tests (and is better tooled for Spring).

If you have no choice, first thing to know is that annotations like `@WithMockUser` and `@WithMockKeyckloakAuth` won't work.
The reason is Cucumber does not support spring `WithSecurityContextTestExecutionListener` around scenarios (`TestExecutionListener` are executed before and after JUnit tests). And [they don't want to](https://github.com/cucumber/cucumber-jvm/issues/2408).

As a consequence, test security context setup must be done manually in `@Given` steps. The only help this lib can bring is with the `OpenidClaimSetBuilder` builders it exposes.

## Minimal sample adapted from [gh-29](https://github.com/ch4mpy/spring-addons/issues/29)

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

  Scenario: Unauthorized users should not be able to access greetings
    Given user is not authenticated
    When a get request is sent to greeting endpoint
    Then 401 is returned
```

Helper to instantiate test `JwtAuthenticationToken`
```java
public class TestJwtAuthenticationTokenBuilder {
    protected final OpenidClaimSetBuilder claimsBuilder;
    private final Set<String> authorities;
    private String bearerString = "machin.truc.chose";
    private Map<String, Object> headers = new HashMap<>(Map.of("machin", "truc"));

    public JwtTestingBuilder() {
        this.claimsBuilder = new OpenidClaimSetBuilder().subject(Defaults.SUBJECT).name(Defaults.AUTH_NAME);
        this.authorities = new HashSet<>(Defaults.AUTHORITIES);
    }

    public JwtAuthenticationToken build() {
        final var claims = claimsBuilder.build();
        final var iat = Instant.now();
        final var exp = iat.plusMillis(60000);
        final var jwt = new Jwt(bearerString, iat, exp, headers, claims);
        return new JwtAuthenticationToken(jwt, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()), claims.getName());
    }

    public JwtTestingBuilder authorities(String... authorities) {
        return authorities(Stream.of(authorities));
    }

    public JwtTestingBuilder authorities(Stream<String> authorities) {
        this.authorities.clear();
        this.authorities.addAll(authorities.toList());
        return this;
    }

    public JwtTestingBuilder claims(Consumer<OpenidClaimSetBuilder> tokenBuilderConsumer) {
        tokenBuilderConsumer.accept(claimsBuilder);
        return this;
    }

    public JwtTestingBuilder bearerString(String bearerString) {
        this.bearerString = bearerString;
        return this;
    }
}
```

Steps:
``` java
public class GreetingControllerSuite {

    @Autowired
    MockMvc mockMvc;

    MvcResult result;

    @Given("user is not authenticated")
    public void unauthenticatedUser() {
        TestSecurityContextHolder.clearContext();
    }

    @Given("the following user roles:")
    public void authenticateAsUser(List<String> rolesTable) {
        TestSecurityContextHolder.clearContext();
        final Stream<String> roles = rolesTable.stream().map(String::trim);
        TestSecurityContextHolder.setAuthentication(new TestJwtAuthenticationTokenBuilder().authorities(roles).build());
    }

    @When("a get request is sent to greeting endpoint")
    public void getGreet() throws Exception {
        result = mockMvc.perform(get("/greet")).andReturn();
    }

    @Then("401 is returned")
    public void unauthorizedStatus() throws Exception {
        assertEquals(401, result.getResponse().getStatus());
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
		"html:target/cucumber" }, extraGlue = "com.c4_soft.springaddons.samples.webmvc.cucumber.extraglue")
public class CucumberIntegrationTest {
}
```

Spring "extraglue":
``` java
package com.c4_soft.springaddons.samples.webmvc.cucumber.extraglue;

...

@CucumberContextConfiguration
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@ContextConfiguration(classes = { SpringBootSampleApp.class })
@AutoConfigureMockMvc
public class CucumberSpringConfiguration {
}
```
