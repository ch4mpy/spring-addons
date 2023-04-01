# `spring-addons-webmvc-jwt-resource-server`
A thin wrapper around `spring-boot-starter-oauth2-resource-server` which pushes auto-configuration one step further for Spring Boot 3 servlet resource servers using JWT decoders.

## 1. Usage
All you need is declaring a dependency on `spring-addons-webmvc-jwt-resource-server` and defining a few properties.

The [`webmvc-jwt-default` sample](https://github.com/ch4mpy/spring-addons/tree/master/samples/webmvc-jwt-default) explains basic configuration and is the best starting point. You might find some more advanced use-cases in [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) and [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples).

## 2. How it works
As any boot starter, a resource file defines what should be loaded: [`src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports) which specifies that two configuration sources should be loaded:
- [`AddonsSecurityBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/AddonsSecurityBeans.java) with a single `OAuth2AuthoritiesConverter` (an alias for `Converter<Map<String, Object>, Collection<? extends GrantedAuthority>>`)
- [`AddonsWebSecurityBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/AddonsWebSecurityBeans.java) which contains a few other beans involved in the creation of a security filter chain for a multi-tenant ready resource server using JWT decoder(s).

Also, as any serious Boot starter, any bean defined there is conditional, so that one way or another, you can deactivate or overload it.

## 3. What is auto configured
The most accurate information about [`AddonsWebSecurityBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/AddonsWebSecurityBeans.java) and [`AddonsSecurityBeans`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-jwt-resource-server/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/AddonsSecurityBeans.java) is in the source and Javadoc, but here is an idea of the auto configured beans.

### 3.1. AddonsSecurityBeans
Provides with an `authoritiesConverter` which is an instance of `ConfigurableClaimSet2AuthoritiesConverter`. This bean is configured with application properties and is able to map spring-security authorities from any claims with prefix and case transformation defined for each claim.

### 3.2. AddonsWebSecurityBeans
Provides with a (non conditional) security filter-chain as well as (conditional) defaults for all the beans required to configure it:
- `springAddonsResourceServerSecurityFilterChain`: applies CORS, CSRF, anonymous, sessionCreationPolicy, SSL, redirect and 401 instead of redirect to login as defined in [`SpringAddonsSecurityProperties`](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-oauth2/src/main/java/com/c4_soft/springaddons/security/oauth2/config/SpringAddonsSecurityProperties.java)
- `authorizePostProcessor`: a bean of type `ExpressionInterceptUrlRegistryPostProcessor` to fine tune access control from java configuration. It applies to all routes not listed in "permit-all" property configuration. Default requires users to be authenticated. **This is a bean to provide in your application configuration if you prefer to define fine-grained access control rules with Java configuration rather than methods security.**
- `httpPostProcessor`: a bean of type `HttpSecurityPostProcessor` to override anything from above auto-configuration. It is called just before the security filter-chain is returned. Default is a no-op.
- `jwtAuthenticationConverter`: a converter from a `Jwt` to something inheriting from `AbstractAuthenticationToken`. The default instantiate a `JwtAuthenticationToken` with username and authorities as configured for the issuer of thi token. The easiest to override the type of `AbstractAuthenticationToken`, is to provide with an `OAuth2AuthenticationFactory` bean.
- `authenticationManagerResolver`: to accept identities issued by more than a single OP, the recommended way is to provide an `JwtIssuerAuthenticationManagerResolver` supporting it. Default keeps a `JwtAuthenticationProvider` with its own `JwtDecoder` for each issuer.
