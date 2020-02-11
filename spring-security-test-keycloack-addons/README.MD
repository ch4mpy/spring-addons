# spring-security-test addons for Keycloak

I propose two different ways to add Keycloak security-context to your Spring unit-tests:
  * `@WithMockKeycloackAuth` annotation, which works for any secured `@Component` testing (including `@Controller` and `@Service`)
  * "flow" APIs for `MockMvc` and `WebTestClient`

## Sample usage
This is taken from unit-tests, so do not easitate to browse it for more samples.

`GreetingApp` is a simple Spring Boot servlet app with a single `GreetingController` relying on a `MessageService`.

There are security rules at 3 different places: `MessageService`, `GreetingController` and `SecurityConfig`.

``` java
@RunWith(SpringRunner.class)
@WebMvcTest(GreetingController.class)
@ContextConfiguration(classes = GreetingApp.class)
@ComponentScan(basePackageClasses = { KeycloakSecurityComponents.class, KeycloakSpringBootConfigResolver.class })
public class GreetingControllerTests extends ServletKeycloakAuthUnitTestingSupport {
	@MockBean
	MessageService messageService;

	@Test
	@WithMockKeycloackAuth("TESTER")
	public void whenUserIsNotGrantedWithAuthorizedPersonelThenSecretRouteIsNotAccessible() throws Exception {
		mockMvc().get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	@WithMockKeycloackAuth("AUTHORIZED_PERSONNEL")
	public void whenUserIsGrantedWithAuthorizedPersonelThenSecretRouteIsAccessible() throws Exception {
		mockMvc().get("/secured-route").andExpect(content().string(is("secret route")));
	}

	@Test
	@WithMockKeycloackAuth(name = "ch4mpy", roles = "TESTER")
	public void whenGreetIsReachedWithValidSecurityContextThenUserIsActuallyGreeted() throws Exception {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final var auth = (Authentication) invocation.getArgument(0);
			return String.format("Hello %s! You are granted with %s.", auth.getName(),
					auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
		});

		mockMvc().get("/greet").andExpect(content().string(is("Hello ch4mpy! You are granted with [ROLE_TESTER].")));
	}
}
```

Same sample with servlet "flow" API:
```java
@RunWith(SpringRunner.class)
@WebMvcTest(GreetingController.class)
@ContextConfiguration(classes = GreetingApp.class)
@ComponentScan(basePackageClasses = { KeycloakSecurityComponents.class, KeycloakSpringBootConfigResolver.class })
public class GreetingControllerTest extends ServletKeycloakAuthUnitTestingSupport {
	@MockBean
	MessageService messageService;

	@Test
	public void whenGreetIsReachedWithValidSecurityContextThenUserIsActuallyGreeted() throws Exception {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final var auth = (Authentication) invocation.getArgument(0);
			return String.format("Hello %s! You are granted with %s.", auth.getName(),
					auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
		});

		mockMvc().with(authentication().name("ch4mpy").roles("TESTER")).get("/greet")
				.andExpect(content().string(is("Hello ch4mpy! You are granted with [ROLE_TESTER].")));
	}

	@Test
	public void whenUserIsNotGrantedWithAuthorizedPersonelThenSecretRouteIsNotAccessible() throws Exception {
		mockMvc().with(authentication().roles("TESTER")).get("/secured-route").andExpect(status().isForbidden());
	}

	@Test
	public void whenUserIsGrantedWithAuthorizedPersonelThenSecretRouteIsAccessible() throws Exception {
		mockMvc().with(authentication().roles("AUTHORIZED_PERSONNEL")).get("/secured-route")
				.andExpect(content().string(is("secret route")));
	}

	@Test
	public void whenUserIsNotGrantedWithAuthorizedPersonelThenSecretMethodIsNotAccessible() throws Exception {
		mockMvc().with(authentication().roles("TESTER")).get("/secured-method").andExpect(status().isForbidden());
	}

	@Test
	public void whenUserIsGrantedWithAuthorizedPersonelThenSecretMethodIsAccessible() throws Exception {
		mockMvc().with(authentication().roles("AUTHORIZED_PERSONNEL")).get("/secured-method")
				.andExpect(content().string(is("secret method")));
	}

}
```