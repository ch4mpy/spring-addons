# spring-addons-webflux-test

Set of tools I find useful to test Spring reactive web apps (webflux).

``` xml
    <dependencies>
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-webflux-test</artifactId>
            <version>${com.c4-soft.springaddons.version}</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
```

## `WebTestClient` configurers
I propose two classes implementing both `WebTestClientConfigurer` and `MockServerConfigurer` to use with `WebTestClient`:
 * `MockAuthenticationWebTestClientConfigurer` to use a Mockito mock of an `Authentication` descendent of your choice (any type implementing `Authentication`)
 * `OidcIdAuthenticationTokenWebTestClientConfigurer` to have `TestSecurityContext` populated with an ... `OidcIdAuthenticationToken`

Browse unit tests to see more samples:
 ``` java
import static com.c4_soft.springaddons.security.oauth2.test.webflux.MockAuthenticationWebTestClientConfigurer.mockAuthentication;

    @Test
    public void testAccessSecuredMethodWithoutRequiredAuthority() {
        client.mutateWith(mockAuthentication()).get("/secured-method")
            .expectStatus().isForbidden();
    }
 ```
 ``` java
import static com.c4_soft.springaddons.security.oauth2.test.webflux.OidcIdAuthenticationTokenWebTestClientConfigurer.oidcId;

    @Test
    public void testDefaultAccessTokenConfigurer() {
        client.mutateWith(oidcId()).get("/greet").expectBody(String.class)
                .isEqualTo("Hello user! You are granted with [].");
    }
 ```

 ## `WebTestClientSupport`
 A wrapper for `WebTestClient` providing with configurable default charset and media-type along with shortcuts for most requests.

 Configuration properties are:
  * `com.c4-soft.springaddons.test.web.default-charset` defaulted to `utf-8`
  * `com.c4-soft.springaddons.test.web.default-media-type` defaulted to `application+json`

``` java
webTestClient.get().uri("/greet").accept(MediaType.APPLICATION_JSON).acceptCharset(Charset.forName("UTF-8")).exchange()
```
becomes
``` java
webTestClient.get("/greet")
```

To use it, you can for instance `@Import(WebTestClientSupport.class)`, scan for components in `com.c4_soft.springaddons.security.oauth2.test.webflux` package, add `WebTestClientSupport.class` to `@ContextConfiguration` classes, etc. (has to be instantiated by Spring for config properties to be parsed / defaulted)