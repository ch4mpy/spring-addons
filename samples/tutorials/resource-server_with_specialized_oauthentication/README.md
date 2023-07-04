# How to extend `OAuthentication<OpenidClaimSet>`

## 1. Overview
Lets says that we have business requirements where security is not role based only.

Lets assume that the authorization server also provides us with a `proxies` claim that contains a map of permissions per user "preferredUsername" (what current user was granted to do on behalf of some other users).

This tutorial will demo
- how to extend `OAuthentication<OpenidClaimSet>` to hold those proxies in addition to authorities
- how to extend security SpEL to easily evaluate proxies granted to authenticated users, OpenID claims or whatever related to security-context

## 2. Project Initialisation
We'll start a spring-boot 3 project with the help of https://start.spring.io/
Following dependencies will be needed:
- lombok

Then add dependencies to spring-addons:
- [`spring-addons-webmvc-jwt-resource-server`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-resource-server/6.1.5)
- [`spring-addons-webmvc-jwt-test`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-test/6.1.5)
```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
</dependency>
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-webmvc-jwt-resource-server</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-webmvc-jwt-test</artifactId>
    <version>${spring-addons.version}</version>
    <scope>test</scope>
</dependency>
```

An other option would be to use one of `com.c4-soft.springaddons` archetypes (for instance [`spring-addons-archetypes-webmvc-singlemodule`](https://github.com/ch4mpy/spring-addons/tree/master/archetypes/spring-addons-archetypes-webmvc-singlemodule) or [`spring-addons-archetypes-webflux-singlemodule`](https://github.com/ch4mpy/spring-addons/tree/master/archetypes/spring-addons-archetypes-webflux-singlemodule))

## 3. Web-Security Configuration

### 3.1. `ProxiesClaimSet` and `ProxiesAuthentication`
Lets first define what a `Proxy` is:
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

Now, we'll extend `OpenidClaimSet` to add `proxies` private-claim parsing
```java
@Data
@EqualsAndHashCode(callSuper = true)
public class ProxiesClaimSet extends OpenidClaimSet {
    private static final long serialVersionUID = 38784488788537111L;

    private final Map<String, Proxy> proxies;

    public ProxiesClaimSet(Map<String, Object> claims) {
        super(claims);
        this.proxies = Collections.unmodifiableMap(Optional.ofNullable(proxiesConverter.convert(this)).orElse(Map.of()));
    }

    public Proxy getProxyFor(String username) {
        return proxies.getOrDefault(username, new Proxy(username, getName(), List.of()));
    }

    private static final Converter<OpenidClaimSet, Map<String, Proxy>> proxiesConverter = claims -> {
        if (claims == null) {
            return Map.of();
        }
        @SuppressWarnings("unchecked")
        final var proxiesClaim = (Map<String, List<String>>) claims.get("proxies");
        if (proxiesClaim == null) {
            return Map.of();
        }
        return proxiesClaim
                .entrySet()
                .stream()
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
public class ProxiesAuthentication extends OAuthentication<ProxiesClaimSet> {
    private static final long serialVersionUID = -6247121748050239792L;

    public ProxiesAuthentication(ProxiesClaimSet claims, Collection<? extends GrantedAuthority> authorities, String tokenString) {
        super(claims, authorities, tokenString);
    }

    @Override
    public String getName() {
        return super.getClaims().getPreferredUsername();
    }

    public boolean hasName(String username) {
        return Objects.equals(getName(), username);
    }

    public Proxy getProxyFor(String username) {
        return getClaims().getProxyFor(username);
    }

}
```

### 3.2. Security @Beans
We'll rely on `spring-addons-webmvc-jwt-resource-server` `@AutoConfiguration` and just force authentication converter.
See [`AddonsSecurityBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/AddonsSecurityBeans.java) for provided `@Autoconfiguration`

We'll also extend security SpEL with a few methods to:
- compare current user's username to provided one
- access current user proxy to act on behalf of someone else (specified by username)
- evaluate if current user is granted with one of "nice" authorities

```java
@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {

    @Bean
    OAuth2ClaimsConverter<ProxiesClaimSet> claimsConverter() {
        return claims -> new ProxiesClaimSet(claims);
    }

    @Bean
    Converter<Jwt, ProxiesAuthentication> authenticationFactory(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
        return jwt -> {
            final var claimSet = new ProxiesClaimSet(jwt.getClaims());
            return new ProxiesAuthentication(claimSet, authoritiesConverter.convert(claimSet), jwt.getTokenValue());
        };
    }

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        return new C4MethodSecurityExpressionHandler(ProxiesMethodSecurityExpressionRoot::new);
    }

    static final class ProxiesMethodSecurityExpressionRoot extends C4MethodSecurityExpressionRoot {

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
`application.properties`:
```
# shoud be set to where your authorization-server is
com.c4-soft.springaddons.security.issuers[0].location=https://localhost:8443/realms/master

# shoud be configured with a list of private-claims this authorization-server puts user roles into
# below is default Keycloak conf for a `spring-addons` client with client roles mapper enabled
com.c4-soft.springaddons.security.issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons-public.roles,resource_access.spring-addons-confidential.roles

# use IDE auto-completion or see SpringAddonsSecurityProperties javadoc for complete configuration properties list
```

## 4. Sample `@RestController`
Note the `@PreAuthorize("is(#username) or isNice() or onBehalfOf(#username).can('greet')")` on the second method, which asserts that the user either:
- is greeting himself
- has one of "nice" authorities
- has permission to `greet` on behalf of user with preferred_username equal to `username` `@PathVariable` (the route is `/greet/{username}`)

``` java
@RestController
@RequestMapping("/greet")
@PreAuthorize("isAuthenticated()")
public class GreetingController {

    @GetMapping()
    @PreAuthorize("hasAuthority('NICE')")
    public String getGreeting(ProxiesAuthentication auth) {
        return String
                .format(
                        "Hi %s! You are granted with: %s and can proxy: %s.",
                        auth.getClaims().getPreferredUsername(),
                        auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")),
                        auth.getClaims().getProxies().keySet().stream().collect(Collectors.joining(", ", "[", "]")));
    }

    @GetMapping("/public")
    public String getPublicGreeting() {
        return "Hello world";
    }

    @GetMapping("/on-behalf-of/{username}")
    @PreAuthorize("is(#username) or isNice() or onBehalfOf(#username).can('greet')")
    public String getGreetingFor(@PathVariable("username") String username, Authentication auth) {
        return String.format("Hi %s from %s!", username, auth.getName());
    }
}
```

## 5. Unit-Tests

### 5.1. `@ProxiesAuth`
`@OpenId` populates test security-context with an instance of `OicAuthentication<OpenidClaimSet>`.
Let's create a `@ProxiesAuth` annotation to inject an instance of `ProxiesAuthentication` instead (with configurable proxies)
```java
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = ProxiesAuth.ProxiesAuthenticationFactory.class)
public @interface ProxiesAuth {

    @AliasFor("authorities")
    String[] value() default {};

    @AliasFor("value")
    String[] authorities() default {};

    OpenIdClaims claims() default @OpenIdClaims();

    Proxy[] proxies() default {};

    String bearerString() default "machin.truc.chose";

    @AliasFor(annotation = WithSecurityContext.class)
    TestExecutionEvent setupBefore()

    default TestExecutionEvent.TEST_METHOD;

    @Target({ ElementType.METHOD, ElementType.TYPE })
    @Retention(RetentionPolicy.RUNTIME)
    public static @interface Proxy {
        String onBehalfOf();

        String[] can() default {};
    }

    public static final class ProxiesAuthenticationFactory extends AbstractAnnotatedAuthenticationBuilder<ProxiesAuth, ProxiesAuthentication> {
        @Override
        public ProxiesAuthentication authentication(ProxiesAuth annotation) {
            final var openidClaims = super.claims(annotation.claims());
            @SuppressWarnings("unchecked")
            final var proxiesClaim = (HashMap<String, List<String>>) openidClaims.getOrDefault("proxies", new HashMap<>());
            Stream.of(annotation.proxies()).forEach(proxy -> {
                proxiesClaim.put(proxy.onBehalfOf(), Stream.of(proxy.can()).toList());
            });
            openidClaims.put("proxies", proxiesClaim);

            return new ProxiesAuthentication(new ProxiesClaimSet(openidClaims), super.authorities(annotation.authorities()), annotation.bearerString());
        }
    }
}
```

### 5.2. Controller Unit-Tests
```java
package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.jwt.AutoConfigureAddonsSecurity;
import com.c4soft.springaddons.tutorials.ProxiesAuth.Proxy;

@WebMvcTest(GreetingController.class)
@AutoConfigureAddonsSecurity
@Import({ WebSecurityConfig.class })
class GreetingControllerTest {

    @Autowired
    MockMvcSupport mockMvc;

    // @formatter:off
    @Test
    void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
        mockMvc
                .get("/greet")
                .andExpect(status().isUnauthorized());
    }

    @Test
    void givenRequestIsAnonymous_whenGreetPublic_thenOk() throws Exception {
        mockMvc
                .get("/greet/public")
                .andExpect(status().isOk())
                .andExpect(content().string("Hello world"));
    }

    @Test
    @ProxiesAuth(
        authorities = { "NICE", "AUTHOR" },
        claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"),
        proxies = {
            @Proxy(onBehalfOf = "machin", can = { "truc", "bidule" }),
            @Proxy(onBehalfOf = "chose") })
    void givenUserIsGrantedWithNice_whenGreet_thenOk() throws Exception {
        mockMvc
                .get("/greet")
                .andExpect(status().isOk())
                .andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR] and can proxy: [chose, machin]."));
    }

    @Test
    @ProxiesAuth(authorities = { "AUTHOR" })
    void givenUserIsNotGrantedWithNice_whenGreet_thenForbidden() throws Exception {
        mockMvc.get("/greet").andExpect(status().isForbidden());
    }

    @Test
    @ProxiesAuth(
            authorities = { "AUTHOR" },
            claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"),
            proxies = { @Proxy(onBehalfOf = "ch4mpy", can = { "greet" }) })
    void givenUserIsNotGrantedWithNiceButHasProxyForGreetedUser_whenGreetOnBehalfOf_thenOk() throws Exception {
        mockMvc.get("/greet/on-behalf-of/ch4mpy").andExpect(status().isOk()).andExpect(content().string("Hi ch4mpy from Tonton Pirate!"));
    }

    @Test
    @ProxiesAuth(
            authorities = { "AUTHOR", "ROLE_NICE_GUY" },
            claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
    void givenUserIsGrantedWithNice_whenGreetOnBehalfOf_thenOk() throws Exception {
        mockMvc.get("/greet/on-behalf-of/ch4mpy").andExpect(status().isOk()).andExpect(content().string("Hi ch4mpy from Tonton Pirate!"));
    }

    @Test
    @ProxiesAuth(
            authorities = { "AUTHOR" },
            claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"),
            proxies = { @Proxy(onBehalfOf = "jwacongne", can = { "greet" }) })
    void givenUserIsNotGrantedWithNiceAndHasNoProxyForGreetedUser_whenGreetOnBehalfOf_thenForbidden() throws Exception {
        mockMvc.get("/greet/on-behalf-of/greeted").andExpect(status().isForbidden());
    }

    @Test
    @ProxiesAuth(
            authorities = { "AUTHOR" },
            claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
    void givenUserIsGreetingHimself_whenGreetOnBehalfOf_thenOk() throws Exception {
        mockMvc.get("/greet/on-behalf-of/Tonton Pirate").andExpect(status().isOk()).andExpect(content().string("Hi Tonton Pirate from Tonton Pirate!"));
    }
    // @formatter:on
}
```

# 6. Conclussion
This sample was guiding you to build a servlet application (webmvc) with JWT decoder and an `Authentication` of your own. If you need help to configure a resource server for webflux (reactive)  or access token introspection, please refer to [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples).
