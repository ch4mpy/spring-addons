# Unit & Integration Testing Applications Using `spring-addons-starter-oidc`

`spring-addons-starter-oidc-test` builds on top of [`spring-addons-oauth2-test`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test) and adds:
- annotations to apply `spring-addons-starter-oidc` auto-configuration to tests security-context
- thin wrappers around `MockMvc` and `WebTestClient` which make tests requests even easier

## Preparing Test Context
`@AutoConfigureAddons*` import various parts of `spring-addons-starter-oidc` auto-configuration in your test context. You should use it in addition to importing your own `SecurityConfig` (if any).

```java
@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
@Import({ SecurityConfig.class })
class GreetingControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isUnauthorized());
	}

	@Test
	@WithJwt("ch4mp.json")
	void givenUserIsGrantedWithNice_whenGreet_thenOk() throws Exception {
		mockMvc.get("/greet")
			.andExpect(status().isOk())
			.andExpect(content().string("Hi ch4mp! You are granted with: [NICE, AUTHOR] and can proxy: [chose, machin]."));
	}
}
```

## `MockMvcSupport` and `WebTestClientSupport`
These two are thin wrappers around respectively `MockMvc` and `WebTestClient` to add the following features:
- shortcuts for simple queries (those without request parameter, fancy header or cookie)
- set default "Accept" and "Content-Type" headers according `com.c4-soft.springaddons.test.web.default-media-type` test properties
- serialize request body according to Content-type using **registered message converters**: pick the message converter that is actually registered by your (auto)configuration and matches the declared content-type (explicitly provided with the request builder, or defaulted in test configuration or `application/json`)

For instance:
```java
@Autowired
private MockMvc mvc;

@Test
public void createEmployeeAPI() throws Exception 
{
  mvc.perform( MockMvcRequestBuilders
	      .post("/employees")
	      .content(asJsonString(new EmployeeDto(null, "firstName4", "lastName4", "email4@mail.com")))
	      .contentType(MediaType.APPLICATION_JSON)
	      .accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isCreated())
      .andExpect(MockMvcResultMatchers.jsonPath("$.employeeId").exists());
}
 
public static String asJsonString(final Object obj) {
    try {
        return new ObjectMapper().writeValueAsString(obj);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}
```
becomes:
```java
@Autowired
private MockMvcSupport mvc;

@Test
public void createEmployeeAPI() throws Exception 
{
  mvc.post(new EmployeeDto(null, "firstName4", "lastName4", "email4@mail.com"), "/employees")
      .andExpect(status().isCreated())
      .andExpect(MockMvcResultMatchers.jsonPath("$.employeeId").exists());
}
```