# How to extend `OAuthentication<OpenidClaimSet>`

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that sources compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Overview
Let's say that we have business requirements where security is not role based only.

Let's assume that the authorization server also provides us with a `proxies` claim that contains a map of permissions per user "preferredUsername" (what current user was granted to do on behalf of some other users).

This tutorial will demo
- how to extend `OAuthentication<OpenidClaimSet>` to hold those proxies in addition to authorities
- how to extend security SpEL to easily evaluate proxies granted to authenticated users, OpenID claims or whatever related to security-context

## 2. Project Initialisation
We'll start a spring-boot 3 project with the help of https://start.spring.io/
Following dependencies will be needed:
- lombok

Then add dependencies to spring-addons:
- [`spring-addons-starter-oidc`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-starter-oidc)
- [`spring-addons-starter-oidc-test`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-starter-oidc-test) with `test` scope
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc-test</artifactId>
    <version>${spring-addons.version}</version>
    <scope>test</scope>
</dependency>
```

## 3. Web-Security Configuration

### 3.1. `ProxiesClaimSet` and `ProxiesAuthentication`
Let's first define what a `Proxy` is:
```java
@Data
public class Proxy implements Serializable {
  private static final long serialVersionUID = 8853377414305913148L;

  private final String proxiedUsername;
  private final String tenantUsername;
  private final Set<String> permissions;

  public Proxy(String proxiedUsername, String tenantUsername, Collection<String> permissions) {
    this.proxiedUsername = proxiedUsername;
    this.tenantUsername = tenantUsername;
    this.permissions = Collections.unmodifiableSet(new HashSet<>(permissions));
  }

  public boolean can(String permission) {
    return permissions.contains(permission);
  }
}
```

Now, we'll extend `OpenidToken` to add `proxies` private-claim parsing
```java
@Data
@EqualsAndHashCode(callSuper = true)
public class ProxiesToken extends OpenidToken {
  private static final long serialVersionUID = 2859979941152449048L;

  private final Map<String, Proxy> proxies;

  public ProxiesToken(Map<String, Object> claims, String tokenValue) {
    super(claims, StandardClaimNames.PREFERRED_USERNAME, tokenValue);
    this.proxies = Collections
        .unmodifiableMap(Optional.ofNullable(proxiesConverter.convert(this)).orElse(Map.of()));
  }

  public Proxy getProxyFor(String username) {
    return proxies.getOrDefault(username, new Proxy(username, getName(), List.of()));
  }

  private static final Converter<OpenidClaimSet, Map<String, Proxy>> proxiesConverter = claims -> {
    @SuppressWarnings("unchecked")
    final var proxiesClaim = (Map<String, List<String>>) claims.get("proxies");
    if (proxiesClaim == null) {
      return Map.of();
    }
    return proxiesClaim.entrySet().stream()
        .map(e -> new Proxy(e.getKey(), claims.getPreferredUsername(), e.getValue()))
        .collect(Collectors.toMap(Proxy::getProxiedUsername, p -> p));
  };
}
```
And finally extend `OAuthentication` to 
- override `getName()` (users are identified by preferred_username in this tutorial)
- provide direct accessor to a proxy for given user (from ProxiesClaimSet above)
```java
@Data
@EqualsAndHashCode(callSuper = true)
public class ProxiesAuthentication extends OAuthentication<ProxiesToken> {
  private static final long serialVersionUID = 447991554788295331L;

  public ProxiesAuthentication(ProxiesToken token,
      Collection<? extends GrantedAuthority> authorities) {
    super(token, authorities);
  }

  public boolean hasName(String username) {
    return Objects.equals(getName(), username);
  }

  public Proxy getProxyFor(String username) {
    return getAttributes().getProxyFor(username);
  }
}
```

### 3.2. Security @Beans
We'll rely on `spring-addons-starter-oidc` `@AutoConfiguration` and just force authentication converter.

We'll also extend security SpEL with a few methods to:
- compare current user's username to provided one
- access current user proxy to act on behalf of someone else (specified by username)
- evaluate if current user is granted with one of "nice" authorities

```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

  @Bean
  JwtAbstractAuthenticationTokenConverter authenticationConverter(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
    return jwt -> {
      final var token = new ProxiesToken(jwt.getClaims(), jwt.getTokenValue());
      return new ProxiesAuthentication(token, authoritiesConverter.convert(token));
    };
  }

  @Bean
  static MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
    return new SpringAddonsMethodSecurityExpressionHandler(
        ProxiesMethodSecurityExpressionRoot::new);
  }

  static final class ProxiesMethodSecurityExpressionRoot
      extends SpringAddonsMethodSecurityExpressionRoot {

    public boolean is(String preferredUsername) {
      return Objects.equals(preferredUsername, getAuthentication().getName());
    }

    public Proxy onBehalfOf(String proxiedUsername) {
      return get(ProxiesAuthentication.class).map(a -> a.getProxyFor(proxiedUsername))
          .orElse(new Proxy(proxiedUsername, getAuthentication().getName(), List.of()));
    }

    public boolean isNice() {
      return hasAnyAuthority("NICE", "SUPER_COOL");
    }
  }
}
```
### 3.3. Configuration Properties
`application.yml`:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${keycloak-issuer}
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - iss: ${cognito-issuer}
          username-claim: username
          authorities:
          - path: cognito:groups
        - iss: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: $['https://c4-soft.com/user']['roles']
          - path: $.permissions
        resourceserver:
          cors:
          - path: /**
            allowed-origin-patterns: ${origins}
          permit-all:
          - "/greet/public"
```

## 4. Sample `@RestController`
Note the `@PreAuthorize("is(#username) or isNice() or onBehalfOf(#username).can('greet')")` on the second method, which asserts that the user either:
- is greeting himself
- has one of "nice" authorities
- has permission to `greet` on behalf of user with preferred_username equal to `username` `@PathVariable` (the route is `/greet/{username}`)

``` java
@RestController
@RequestMapping("/greet")
public class GreetingController {

    @GetMapping()
    @PreAuthorize("hasAuthority('NICE')")
    public String getGreeting(ProxiesAuthentication auth) {
        return "Hi %s! You are granted with: %s and can proxy: %s.".formatted(
                auth.getName(),
                auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")),
                auth.getClaims().getProxies().keySet().stream().collect(Collectors.joining(", ", "[", "]")));
    }

    @GetMapping("/public")
    public String getPublicGreeting() {
        return "Hello world";
    }

    @GetMapping("/on-behalf-of/{username}")
    @PreAuthorize("is(#username) or isNice() or onBehalfOf(#username).can('greet')")
    public String getGreetingFor(@PathVariable(name = "username") String username, Authentication auth) {
        return "Hi %s from %s!".formatted(username, auth.getName());
    }
}
```

## 5. Unit-Tests

The authentication factory behind `@WithJwt` uses the authentication converter in the security context if it finds any.

As we exposed ours as a bean, `@WithJwt` will populate the test security context with `ProxiesAuthentication` instances. But be careful that mutators from `spring-security-tests` (like `.jwt()`) wouldn't do so.
```java
@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
@Import({ SecurityConfig.class })
class GreetingControllerTest {

    @Autowired
    MockMvcSupport mockMvc;

    // @formatter:off
    @Test
    @WithAnonymousUser
    void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
        mockMvc.get("/greet")
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithAnonymousUser
    void givenRequestIsAnonymous_whenGreetPublic_thenOk() throws Exception {
        mockMvc.get("/greet/public")
            .andExpect(status().isOk())
            .andExpect(content().string("Hello world"));
    }

    @Test
    @WithJwt("ch4mp.json")
    void givenUserIsGrantedWithNice_whenGreet_thenOk() throws Exception {
        mockMvc.get("/greet")
            .andExpect(status().isOk())
            .andExpect(content().string("Hi ch4mp! You are granted with: [NICE, AUTHOR] and can proxy: [chose, machin]."));
    }

    @Test
    @WithJwt("tonton_proxy_ch4mp.json")
    void givenUserIsNotGrantedWithNice_whenGreet_thenForbidden() throws Exception {
        mockMvc.get("/greet")
            .andExpect(status().isForbidden());
    }

    @Test
    @WithJwt("tonton_proxy_ch4mp.json")
    void givenUserIsNotGrantedWithNiceButHasProxyForGreetedUser_whenGreetOnBehalfOf_thenOk() throws Exception {
        mockMvc.get("/greet/on-behalf-of/ch4mp")
            .andExpect(status().isOk())
            .andExpect(content().string("Hi ch4mp from Tonton Pirate!"));
    }

    @Test
    @WithJwt("ch4mp.json")
    void givenUserIsGrantedWithNice_whenGreetOnBehalfOf_thenOk() throws Exception {
        mockMvc.get("/greet/on-behalf-of/Tonton Pirate")
            .andExpect(status().isOk())
            .andExpect(content().string("Hi Tonton Pirate from ch4mp!"));
    }

    @Test
    @WithJwt("tonton_proxy_ch4mp.json")
    void givenUserIsNotGrantedWithNiceAndHasNoProxyForGreetedUser_whenGreetOnBehalfOf_thenForbidden() throws Exception {
        mockMvc.get("/greet/on-behalf-of/greeted")
            .andExpect(status().isForbidden());
    }

    @Test
    @WithJwt("tonton_proxy_ch4mp.json")
    void givenUserIsGreetingHimself_whenGreetOnBehalfOf_thenOk() throws Exception {
        mockMvc.get("/greet/on-behalf-of/Tonton Pirate")
            .andExpect(status().isOk())
            .andExpect(content().string("Hi Tonton Pirate from Tonton Pirate!"));
    }
    // @formatter:on
}

```

# 6. Conclusion
This sample was guiding you to build a servlet application (webmvc) with JWT decoder and an `Authentication` of your own. If you need help to configure a resource server for webflux (reactive)  or access token introspection, please refer to [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples).
