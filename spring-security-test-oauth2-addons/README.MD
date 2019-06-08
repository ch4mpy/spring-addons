# spring-security-test addons
What I propose here is a set of tools to ease unit-testing components tied to spring-security.
For now, this is limited to OAuth2 testing, but could grow.

1. [Abstract](#abstract)<br/>
  1.1. [Motivation](#abstract.motiv)<br/>
  1.2. [Framework contribution](#abstract.contrib)<br/>
  1.3. [Reasons for forking](#abstract.fork)<br/>
2. [Usage](#usage)<br/>
  2.1. [@Controller test setup](#usage.controller-setup)<br/>
  2.2. [@Component test setup](#usage.component-setup)<br/>
  2.3. [OAuth2 test annotations](#usage.annotations)<br/>
  2.4. [OAuth2 MockMvc request post-processor and WebTestClient configurer](#usage.flow)<br/>

<a name="abstract"/>

## Abstract you can skip
I initiated this lib to start working with Spring 5 resource-server before OAuth2 support is fully added to spring-security.
Some of it was integrated to spring-security-test, but at the price of removing features I like.
I also provide tooling for testing apps using extensions of my own to spring-security.

<a name="abstract.motiv"/>

### Motivation for this lib
At time I got interested into spring-security OAuth2, there were not much support for unit-testing.
As, IMO, security is a major business concern, it doesn't make sense to unit-test controllers and services without security.
As so, a correctly configured `SecurityContext` is a "must have" when running unit-tests and 
I couldn't imagine using OAuth2 if I couldn't easily write unit-tests.

When I write "business concern", I mean my use case are generally expressed as 
"As a [user_role], when I [screen_interaction], then [expected_result]"
and so many of it have `expected_result` look like "should be able to ...", "should see all of ... and it only", etc.
So spring security expressions are actually part of business needs implementations I definitely wanted to finely unit-test, 
not just cover partially in integration-tests.

<a name="abstract.contrib"/>

### Attempts to contribute to the framework
A year after I created my first OAuth2 test annotations, as it still proved useful, I proposed to contribute it to the framework,
which was rejected as based on deprecated spring-security-oauth2 lib. I then started this for Spring 5.

During the review, the Spring team and chose different tradeoffs on usability:
* defining the token only (my way) requires the tester to provide the test framework 
  with a way to convert it to a `Collection<GratedAuthority>` (the application authorities-converter or a 
  mocked the authorization service)
* defining Spring granted-authorities and token separately simplifies configuration 
  and removes the dependency on authorities conversion but requires the tester to **manually 
  keep the synch between the token definition and registered authorities**

<a name="abstract.fork"/>

### Reasons for forking this lib from contributed code
First, IMO, there are good reasons for choosing to define the root element (the token) instead 
of authorities for `JwtAuthenticationToken`:
1. spring security expressions can be about anything (specifically any claim). As so, defining just authorities can't 
   be enough to satisfy security test needs
2. by default, authorities are derived from the `Jwt` using a `Converter`, which should be unique and 
   well known for a given application
3. `JwtAuthenticationToken` contain both the `Jwt` and authorities
4. defining separately twice the same value is always a bad idea. Here, it would sooner 
   or later lead to test authentication inconsistencies (different `Collection<GrantedAuthority>` from what would be derived from token claims).
   Because of 1. (security not always being authority based) that can cause very subtle test bugs, which is hardly acceptable.

Second, at time I write this lines, Spring team shows interest for `JwtAuthenticationToken` 
"flow APIs" (servlet and reactive) only when I already have implemented support for:
* `OAuth2IntrospectionAuthenticationToken` in addition to `JwtAuthenticationToken`
* annotations (`@WithMockJwt`, `@WithMockIntrospectionToken`) 
  in addition to flow APIs, which enables to test not only `@Controllers`, but also 
  any kind of `@Component` such as services.

Last, Spring team sticks to existing code patterns which could sometimes be improved. My experience 
at contributing being rather painful, it should actually be far less time consuming to 
maintain this lib against framework evolutions than trying to improve the framework 
:-/

<a name="usage"/>

## Usage
With Spring 5, spring-security-test provides ways to inject any kind of `Authorization` 
in the test `SecurityContext`, including OAuth2 implementations. So it is possible 
to do something like:
``` java
mockMvc.perform(get("/greeting").with(authentication(new JwtAuthenticationToken(jwt, authorities)))
    .andExpect(...)
``` 
This lib proposes helpers to build the token and OAuth2 `Authentication` implementations.

<a name="usage.controller-setup"/>

### Test setup for a JWT `@Controller`
Spring needs a `JwtDecoder` to be registered, even if it won't be used.

If you stick with `JwtAuthenticationToken`, but prefer to use this lib annotation or flow api,
you'll also have to register an authorities converter in application context.

Here is an easy way to achieve both:
``` java
@Import(ShowcaseControllerTests.Conf.class)
public class ShowcaseControllerTests {

	//necessary for JWT security only
    @MockBean
    JwtDecoder jwtDecoder;
    
    //necessary to build test JwtAuthenticationToken only (can be skipped for OAuth2ClaimSetAuthentication and OAuth2IntrospectionToken)
    @Configuration
    static class Conf {
        @Bean
        Converter<Jwt, Collection<GrantedAuthority>> jwtAuthoritiesConverter() {
            return new JwtGrantedAuthoritiesConverter();
        }
    }
}
```

<a name="usage.component-setup"/>

### Test setup for a secured `@Component`
You need to load security context configuration. Do not forget JWT related beans described 
above (decoder and authorities converter) if relevant.
Please refer to [MessageServiceTests](https://github.com/ch4mpy/spring-addons/blob/master/spring-security-test-oauth2-addons/src/test/java/org/springframework/security/test/context/support/MessageServiceTests.java) 
for a complete working sample.

<a name="usage.annotations"/>

### Annotations
I favor annotations because it enables to test any kind of `@Component` when both `MockMvc` 
post-processors and `WebTestClient` configurers are limited to `@Controllers`.
Following samples are for JWT authentication. Translating to introspection
is straight forward, IDE auto-completion should be enough once you got the idea.

I provide quite a few implementations:
 * `@WithMockJwtClaimSet` configures the security context with an `OAuth2ClaimSetAuthentication<WithAuthoritiesJwtClaimSet>`
 * `@WithMockIntrospectionClaimSet` configures the security context with an `OAuth2ClaimSetAuthentication<WithAuthoritiesIntrospectionClaimSet>`
 * `@WithMockJwtClaimSet` configures the security context with a `JwtAuthenticationToken`
 * `@WithMockIntrospection` configures the security context with an `OAuth2IntrospectionAuthenticationToken`

Basic sample covering most use-cases:
``` java
@Test
@WithMockJwtClaimSet(name = "ch4mpy", authorities = "AUTHORIZED_PERSONEL")
public void demo() throws Exception {
    mockMvc.perform(get("/greeting"))
        .andExpect(content().string(is("Hello, ch4mpy!")));

    mockMvc.perform(get("/restricted/greeting"))
        .andExpect(content().string(is("Welcome to restricted area.")));
}
```

Configuring `Map<String, Object>` such as claims, headers, token-attributes, etc.:
``` java
    @Test
    @WithMockJwtClaimSet(claims = {
            @StringAttribute(name = JwtClaimNames.SUB, value = "ch4mpy"),
            @StringAttribute(name = "authorities", value = "AUTHORIZED_PERSONEL") })
    public void demoWithMockJwtClaims() throws Exception {
        mockMvc.perform(get("/greeting"))
            .andExpect(content().string(is("Hello, ch4mpy!")));

        mockMvc.perform(get("/restricted/greeting"))
            .andExpect(content().string(is("Welcome to restricted area.")));
    }
```

<a name="usage.flow"/>

### Flow APIs

#### Provided builders

`OAuth2ClaimSetAuthentication` constructor is simple enough for builder to be useless,
but if you chose to keep one of spring provided `Authentication` implementation you might find one of following useful:
* `JwtAuthenticationTokenTestingBuilder` (requires an authorities converter)
* `OAuth2IntrospectionAuthenticationTokenTestingBuilder`

#### Sample usage with `MockMvc` request post-processor
Static imports:
``` java
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.*;
```

OAuth2ClaimSetAuthentication request post-processor sample:
``` java
    @Test
    public void demo() throws Exception {
        mockMvc.perform(get("/jwt").with(jwtOauth2Authentication()))
            .andExpect(content().string(is("{sub=user}")));

        mockMvc.perform(get("/restricted/greeting").with(jwtOauth2Authentication(claims -> claims.authorities("AUTHORIZED_PERSONEL"))))
            .andExpect(content().string(is("Welcome to restricted area.")));
    }
```

`JwtAuthenticationTokenTestingBuilder` is slightly more complicated to use because 
of required authorities converter:
``` java
    @Autowired
    Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

    @Test
    public void demo() throws Exception {
        mockMvc.perform(get("/jwt").with(jwt(authoritiesConverter)))
            .andExpect(content().string(is("{sub=user}")));

        mockMvc.perform(get("/restricted/greeting").with(jwt(authoritiesConverter).scopes("AUTHORIZED_PERSONEL")))
            .andExpect(content().string(is("Welcome to restricted area.")));
    }
```

#### Sample usage with `WebTestClient` configurer
Static imports and helper method for other tests
``` java
import static org.springframework.security.test.web.reactive.server.OAuth2SecurityMockServerConfigurers.*;

    public static WebTestClient.Builder clientBuilder() {
        return WebTestClient.bindToController(new TestController())
                .webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
                .apply(springSecurity())
                .configureClient()
                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
    }
```

Sample for OAuth2CliamSetAuthentication:
``` java
    @Test
    public void demo() throws Exception {
        clientBuilder()
                .apply(mockIntrospectionClaimSet()).build()
                .get().uri("/greet").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("Hello user!");
        clientBuilder()
                .apply(mockIntrospectionClaimSet(claims -> claims.authorities("AUTHORIZED_PERSONEL"))).build()
                .get().uri("/restricted/greeting").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("Welcome to restricted area.");
    }
    
```

Samples for OAuth2IntrospectionAuthenticationToken:
``` java
    @Test
    public void demo() {
        clientBuilder()
                .apply(mockAccessToken().username("ch4mpy")).build()
                .get().uri("/greet").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("Hello ch4mpy!");

        clientBuilder()
                .apply(mockAccessToken()).build()
                .get().uri("/authorities").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).isEqualTo("[SCOPE_USER]");

        final String body = clientBuilder()
                .apply(mockAccessToken().scopes("message:read", "message:write")).build()
                .get().uri("/authorities").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).returnResult().getResponseBody();
                
        assertThat(body).contains("SCOPE_message:read");
        assertThat(body).contains("SCOPE_message:write");
    }
```

#### TestingAuthenticationToken
This one is special: it enables to define granted-authorities directly and any Object as principal,  
which provides with a lot of flexibility.

Demo where @Controller does not care about principal (or is OK if it's just the "name" 
string):
``` java
    @Test
    public void demoTestingToken() throws Exception {
        mockMvc.perform(get("/restricted/greeting").with(testingToken().authority("AUTHORIZED_PERSONEL")))
                .andExpect(content().string(is("Welcome to restricted area.")));
    }
```

**There is no link between `principal` and 
`authorities` inside `TestingAuthenticationToken`** so, if there is a business link 
between the two (if you use an OAuth2 token as principal for instance) you should 
carefully keep the synch externally (manually or generate one from the other):
``` java
    @Autowired
    Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

    @Test
    public void demoTestingTokenWithPrincipal() throws Exception {
        final Jwt principal = new JwtBuilder()
            .subject("ch4mpy")
            .claim("authorities", "AUTHORIZED_PERSONEL").build();
        
        mockMvc.perform(get("/restricted/greeting").with(testingToken()
                        .principal(principal)
                        .authorities(authoritiesConverter.convert(principal))))
                .andExpect(content().string(is("Welcome to restricted area.")));
    }
```
This assumes security configuration defines a bean like:
``` java
    @Bean
    Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
        return jwt -> Stream.of(jwt.getClaimAsString("authorities").split(" "))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }
```