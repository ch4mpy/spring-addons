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
I initiated this lib to start working with Spring 5 resource-server before OAuth2 support is fully added to spring-security
(and keep some features I like but lost in integration process).

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
which was first rejected as based on deprecated spring-security-oauth2 lib. I then started this for Spring 5.

During the review, some divergences emerged with Spring team: they consider `GrantedAuthority` 
to be at the root of authorization, when, for OAuth2, I think this should be the token, 
as stated by [RFC-6749 section-1.4](https://tools.ietf.org/html/rfc6749#section-1.4): 
_An access token is a string representing an authorization issued to the client_.

This different views lead to different tradeoffs:
* defining the token only (my way) requires the tester to provide the test framework 
  with a way to convert it to a `Collection<GratedAuthority>` (the application authorities-converter or a 
  mocked the authorization service)
* defining Spring granted-authorities and token separately simplifies configuration 
  and removes the dependency on authorities conversion but requires the tester to **manually 
  keep the synch between the token definition and registered authorities**

<a name="abstract.fork"/>

### Reasons for forking this lib from contributed code
First, IMO, there are good reasons for choosing to define the root element (the token) instead 
of authorities as usual for spring-security-test:
1. spring security expressions can be about anything. As so, defining just authorities can't 
   be enough to satisfy security test needs
2. authorities are derived from the token using a `Converter`, which should be unique and 
   well known for a given application
3. Spring5 OAuth2 `Authentication` implementations contain both the token and authorities
4. defining separately twice the same value is always a bad idea. Here, it would sooner 
   or later lead to test `Authorization` inconsistencies (different `Collection<GrantedAuthority>` from what would be derived from token claims).
   Because of 1. (security not always being authority based) that can cause very subtle test bugs, which is hardly acceptable.

Second, at time I write this lines, Spring team shows interest for `JwtAuthenticationToken` 
"flow APIs" (servlet and reactive) only when I already have implemented support for:
* `OAuth2IntrospectionAuthenticationToken` and `OAuth2LoginAuthenticationToken` in 
  addition to `JwtAuthenticationToken`
* annotations (`@WithMockJwt`, `@WithMockIntrospectionToken`, `@WithMockOidcIdToken`) 
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
For JWT, this lib requires the authorities converter to be registered in application context.
Spring also needs a `JwtDecoder` to be registered, even if it won't be used.
Here is an easy way to achieve both:
``` java
@Import(ShowcaseControllerTests.Conf.class)
public class ShowcaseControllerTests {

    @MockBean
    JwtDecoder jwtDecoder;

    @Configuration
    static class Conf {
        @Bean
        Converter<Jwt, Collection<GrantedAuthority>> jwtAuthoritiesConverter() {
            return new JwtGrantedAuthoritiesConverter();
        }
    }
}
```
I'd prefer this not to be necessary, but Spring default configuration does not expose authorities converters:
* `JwtAuthenticationConverter` instantiates a `JwtGrantedAuthoritiesConverter` instead 
  of having it injected
* other authentication converters (introspection and openId) do not even allow for authorities converters configuration

I asked for `JwtGrantedAuthoritiesConverter` to be exposed as a `Converter<Jwt, Collection<GrantedAuthority>>`
Bean autowired in `JwtAuthenticationConverter` but it was rejected. Feel free to renew 
the request, maybe will it be accepted some day...

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
Following samples are for JWT authentication. Translating to introspection or openID 
is straight forward, IDE auto-completion should be enough once you got the idea.

Basic sample covering most use-cases:
``` java
@Test
@WithMockJwt(name = "ch4mpy", scopes = "AUTHORIZED_PERSONEL")
public void demoWithMockJwt() throws Exception {
    mockMvc.perform(get("/greeting"))
        .andExpect(content().string(is("Hello, ch4mpy!")));

    mockMvc.perform(get("/restricted/greeting"))
        .andExpect(content().string(is("Welcome to restricted area.")));
}
```

Configuring `Map<String, Object>` such as claims, headers, token-attributes, etc.:
``` java
    @Test
    @WithMockJwt(claims = {
            @StringAttribute(name = JwtClaimNames.SUB, value = "ch4mpy"),
            @StringAttribute(name = "scope", value = "AUTHORIZED_PERSONEL") })
    public void demoWithMockJwtClaims() throws Exception {
        mockMvc.perform(get("/greeting"))
            .andExpect(content().string(is("Hello, ch4mpy!")));

        mockMvc.perform(get("/restricted/greeting"))
            .andExpect(content().string(is("Welcome to restricted area.")));
    }
```

<a name="usage.flow"/>

### Flow APIs
We provide OAuth2 `Authentication` builders to ease interaction with existing `@Controller` testing APIs:
* `MockMvc` `authentication` request post-processor
* `WebTestClient` `mockAuthentication` configurer

#### Provided builders
depending on your application security needs, you might pick one of folowing:
* `SimpleTestingAuthenticationTokenBuilder`, not OAuth2 specific, allows to define 
  user name and authorities
* `JwtAuthenticationTokenTestingBuilder`, helps build authentication based on a JWT 
  token, requires an authorities converter
* `OAuth2IntrospectionAuthenticationTokenTestingBuilder` helps build an authentication 
  based on an opaque access-token
* `OAuth2LoginAuthenticationTokenTestingBuilder`  helps build an authentication based 
  on an OpenId token

#### Sample usage with `MockMvc` request post-processor
`JwtAuthenticationTokenTestingBuilder` is slightly more complicated to use because 
of required authorities converter:
``` java
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.accessToken;
import static org.springframework.security.test.web.servlet.request.OAuth2SecurityMockMvcRequestPostProcessors.oidcId;
```
``` java
    @Autowired
    Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

    @Test
    public void demoJwtAuthenticationBuilder() throws Exception {
        mockMvc.perform(get("/jwt").with(jwt(authoritiesConverter)))
            .andExpect(content().string(is("{sub=user}")));

        mockMvc.perform(get("/restricted/greeting").with(jwt(authoritiesConverter).scopes("AUTHORIZED_PERSONEL")))
            .andExpect(content().string(is("Welcome to restricted area.")));
    }
```

#### Sample usage with `WebTestClient` configurer
``` java
import static org.springframework.security.test.web.reactive.server.OAuth2SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.OAuth2SecurityMockServerConfigurers.mockAccessToken;
import static org.springframework.security.test.web.reactive.server.OAuth2SecurityMockServerConfigurers.mockOidcId;
```
``` java
    public static WebTestClient.Builder clientBuilder() {
        return WebTestClient.bindToController(new TestController())
                .webFilter(new CsrfWebFilter(), new SecurityContextServerWebExchangeWebFilter())
                .apply(springSecurity())
                .configureClient()
                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
    }

    @Test
    public void demoAccessTokenConfigurer() {
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
