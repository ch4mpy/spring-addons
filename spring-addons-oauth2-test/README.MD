# Unit & Integration Testing With Security
Testing method security (`@PreAuthorize`, `@PostFilter`, etc.) requires to configure the security context. `Spring-security-test` provides with `MockMvc` request post-processors and `WebTestClient` mutators to do so, but this requires the context of a request, which limits its usage to testing secured controllers.

To test method security on any type of `@Component` (`@Controller`, off course, but also `@Service` and `@Repository`) there are  only two options: build tests security context by yourself and populate it with stubbed / mocked authentications, or use annotations to do it for you. **This lib contains annotations to configure test security context with OAuth2 authentication at your hand.**

An [article covering the usage of OAuth2 test annotations from this lib](https://www.baeldung.com/spring-oauth-testing-access-control) was published on Baeldung. This, along with all [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) and [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) source-code (which contain a lot of unit and integration testing), should be enough to get you started.

However, since this article was published, test annotations have improved, but **require custom authentication converter to be exposed as a @Bean** (instead of inlining it with a lambda in the `SecurityFilterChain` definition). The authentication factory needs this bean to build the same Authentication instance as you would get at runtime.

**Important warning for those using `@WithJwt` (and since `7.3.0`, `@WithMockJwtAuth`) but not `spring-addons-starter-oidc`**: you should expose your JWT converter as a bean. In practice, instead of inlining the authentication converter in the `SecurityFilterChain` definition, use something like:
```java
@Bean
// It is important that what implements Converter<Jwt, AbstractAuthenticationToken> is exposed as a @Bean
JwtAuthenticationConverter authenticationConverter() {
    final var authenticationConverter = new JwtAuthenticationConverter();
    authenticationConverter.setPrincipalClaimName(StandardClaimNames.PREFERRED_USERNAME);
    authenticationConverter
            .setJwtGrantedAuthoritiesConverter(
                    (jwt) -> Optional
                            .ofNullable(jwt.getClaimAsStringList("roles"))
                            .orElse(List.of())
                            .stream()
                            .map(SimpleGrantedAuthority::new)
                            .map(GrantedAuthority.class::cast)
                            .toList());
    return authenticationConverter;
}

@Bean
// This bean can then be injected in your SecurityFilterChain as follow
SecurityFilterChain securityFilterCHain(HttpSecurity http, Converter<Jwt, AbstractAuthenticationToken> authenticationConverter) throws Exception {
    http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(authenticationConverter)));
    ...
    return http.build();
}
```
This is important for the test annotation to get this authentication converter from the test context (and use it to build the `Authentication` instance it puts in the test security context).

## Sample

Let's consider the following secured `@Service`
```java
@Service
public class SecuredService {
    @PreAuthorize("hasAuthority('NICE')")
    String nice() {
        return "Dear %s, glad to see you!".formatted(SecurityContextHolder.getContext().getAuthentication().getName());
    }
    
    @PreAuthorize("isAuthenticated()")
    String hello() {
        return "Hello %s.".formatted(SecurityContextHolder.getContext().getAuthentication().getName());
    }
}
```
Now, let's assume that you have a staging environment with a few representative users ("personas" if you are familiar with UX), for which you can get sample access tokens, and dump the claims in JSON files in test resources in (by decoding JWTs with a tool like https://jwt.io or introspecting opaque tokens). In the following, we'll consider you have a user named `brice` with `NICE` authority and another one named `igor` without the `NICE` authority. We'll also consider you have dumped sample claim-sets in `brice.json` and `igor.json`.

## Using `@WithMockAuthentication`

When testing RBAC (role-based access control), defining just authorities is frequently enough. Sometimes, defining the `Authentication#name` is necessary and in a few cases, application code needs a specific `Authentication` implementation. `@WithMockAuthentication` was designed to meet these requirements:
```java
@SpringBootTest(classes = { SecurityConfig.class, MessageService.class })
class MessageServiceTests {

	@Autowired
	private SecuredService securedService;
	
	@Test
	@WithMockAuthentication("BAD_BOY")
	void givenUserIsNotGrantedWithNice_whenCallNice_thenThrows() {
		assertThrows(Exception.class, () -> securedService.nice());
	}

	@Test
	@WithMockAuthentication(name = "brice", authorities = "NICE")
	void givenUserIsNice_whenCallNice_thenReturnsGreeting() {
		assertThat(securedService.nice()).isEqualTo("Dear brice, glad to see you!");
	}

	@ParameterizedTest
	@AuthenticationSource(
	    @WithMockAuthentication(name = "brice", authorities = "NICE"),
	    @WithMockAuthentication(name = "ch4mp", authorities = { "VERY_NICE", "AUTHOR" }))
	void givenUserIsAuthenticated_whenCallHello_thenReturnsGreeting(@ParameterizedAuthentication Authentication auth) {
		assertThat(securedService.hello()).isEqualTo("Hello %s.".formatted(auth.getName()));
	}
}
```

## Using `@WithJwt` or `@WithOpaqueToken` with JSON claim-sets

`@WithJwt` and `@WithOpaqueToken` enable to load those claim-sets and turn it into `Authentication` instances.

For the Authentication to be built as at runtime (type, authorities, name, claims, etc.), `@WithJwt` uses your `Converter<Jwt, ? extends AbstractAuthenticationToken>` and `@WithOpaqueToken` the `OpaqueTokenAuthenticationConverter` (or the reactive counterparts in reactive apps).

For the wiring to happen correctly, you need to import `AuthenticationFactoriesTestConf` (it is already imported when using one of `@AddonsWebmvcComponentTest`, `AutoConfigureAddonsWebmvcClientSecurity`, `AutoConfigureAddonsWebmvcResourceServerSecurity` or their reactive counterparts).
```java
@Import(AuthenticationFactoriesTestConf.class) // when using spring-addons-oauth2-test but not spring-addons-starter-oidc
@SpringBootTest(classes = { SecurityConfig.class, MessageService.class })
class MessageServiceTests {

	@Autowired
	private SecuredService securedService;

	@Autowired
	WithJwt.AuthenticationFactory authFactory;
	
	@Test
	@WithJwt("igor.json")
	void givenUserIsIgor_whenCallNice_thenThrows() {
		assertThrows(Exception.class, () -> securedService.nice());
	}

	@Test
	@WithJwt("brice.json")
	void givenUserIsBrice_whenCallNice_thenReturnsGreeting() {
		assertThat(securedService.nice()).isEqualTo("Dear brice, glad to see you!");
	}

	@ParameterizedTest
	@MethodSource("identities")
	void givenUserIsAuthenticated_whenCallHello_thenReturnsGreeting(@ParameterizedAuthentication Authentication auth) {
		assertThat(securedService.hello()).isEqualTo("Hello %s.".formatted(auth.getName()));
	}

	Stream<AbstractAuthenticationToken> identities() {
		return authFactory.authenticationsFrom("brice.json", "igor.json");
	}
}
```
There are we few things worth noting above:
- we are testing a `@Service` having methods decorated with `@PreAuthorize`, without `MockMvc` or `WebTestClient` (and their request post-processors or mutators)
- authorities and username will be coherent with claims during tests (it is not necessarily the case when we declare the 3 separately as done with MockMvc request post-processors and WebTestClient mutators). `WithJwt.AuthenticationFactory` uses the JWT authorities converter found in security configuration. As a consequence, `username` and `authorities` are resolved from claims, just as it is at runtime.
- the claims are loaded from a JSON files in the test classpath
- we are using JUnit 5 `@ParameterizedTest`: the test will run once for each of the authentication in the stream provided  by the `identities` method
- annotations fit so well with BDD (given-when-then): the test pre-conditions (given) are decorating the test instead of cluttering its content like MockMvc request post-processors and WebTestClient mutators do
- annotations can be very brief and expressive

**Important warning for those using `@WithJwt` (and since `7.3.0`, `@WithMockJwtAuth`) but not `spring-addons-starter-oidc`**: you should expose your JWT converter as a bean. In practice, instead of inlining the authentication converter in the `SecurityFilterChain` definition, use something like:
```java
@Bean
// It is important that what implements Converter<Jwt, AbstractAuthenticationToken> is exposed as a @Bean
JwtAuthenticationConverter authenticationConverter() {
    final var authenticationConverter = new JwtAuthenticationConverter();
    authenticationConverter.setPrincipalClaimName(StandardClaimNames.PREFERRED_USERNAME);
    authenticationConverter
            .setJwtGrantedAuthoritiesConverter(
                    (jwt) -> Optional
                            .ofNullable(jwt.getClaimAsStringList("roles"))
                            .orElse(List.of())
                            .stream()
                            .map(SimpleGrantedAuthority::new)
                            .map(GrantedAuthority.class::cast)
                            .toList());
    return authenticationConverter;
}

@Bean
// This bean can then be injected in your SecurityFilterChain as follow
SecurityFilterChain securityFilterCHain(HttpSecurity http, Converter<Jwt, AbstractAuthenticationToken> authenticationConverter) throws Exception {
    http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(authenticationConverter)));
    ...
    return http.build();
}
```
This is important for the test annotation to get this authentication converter from the test context (and use it to build the `Authentication` instance it puts in the test security context).

## Which Annotation to Use

`@WithMockAuthentication` should be enough to test applications with RBAC (role-based access control): it allows to easily define `name` and `authorities`, as well as the Authentication a principal types to mock if your application code expects something specific.

In case your access-control uses more than just name and authorities, you'll probably need to define claim-set details. In this case, `@WithJwt` and `@WithOpaqueToken` can come pretty handy as it uses respectively the JWT or OpaqueToken authentication converter in your security configuration to build the authentication instance, using a JSON payload from the classpath (or a plain Java String): you might just dump payloads of access tokens for representative users in test resources (use a tool like https://jwt.io to easily get those payloads).