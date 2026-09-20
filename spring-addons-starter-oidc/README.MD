# spring-addons-starter-oidc

A Spring Boot starter to use in addition to `spring-boot-starter-oauth2-client` or `spring-boot-starter-oauth2-resource-server` to further **ease OAuth2 configuration with any OpenID Provider, and potentially several heterogeneous ones at a time**.

```xml
<properties>
    <springaddons.version>9.4.0</springaddons.version>
</properties>

<dependencies>
    <!-- the following is a complement (not a replacement) to
    spring-boot-starter-oauth2-resource-server or spring-boot-starter-oauth2-client (or both) -->
    <dependency>
        <groupId>com.c4-soft.springaddons</groupId>
        <artifactId>spring-addons-starter-oidc</artifactId>
        <version>${springaddons.version}</version>
    </dependency>
    <dependency>
        <groupId>com.c4-soft.springaddons</groupId>
        <artifactId>spring-addons-starter-oidc-test</artifactId>
        <version>${springaddons.version}</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

Depending on the classpath and application properties, this starter may auto-configure up to two security filter chain beans with very low precedence: a stateless one with `oauth2ResourceServer`, and a stateful one with `oauth2Login`. Every bean they are built with is `@ConditionalOnMissingBean`, so any default can be taken back one at a time.

## Documentation

The reference lives on the documentation site, one page per concern:

- [Resource servers](https://ch4mpy.github.io/spring-addons/oidc/resource-server/): authorities mapping, authentication converter, multi-tenancy, CORS, access control
- [Clients with `oauth2Login`](https://ch4mpy.github.io/spring-addons/oidc/client/): authorization code, RP-Initiated and Back-Channel Logout, CSRF for single-page applications, post login and logout URIs, concurrent refresh token flows
- [Basic usage](https://ch4mpy.github.io/spring-addons/oidc/usage/): minimal working configurations
- [FAQ](https://ch4mpy.github.io/spring-addons/oidc/faq/): Auth0 audiences, Keycloak realms created at runtime, Microsoft Entra ID, proxies, cookies
- [Risks and mitigations](https://ch4mpy.github.io/spring-addons/oidc/risks/), worth two minutes before adopting
- [What you would write without spring-addons](https://ch4mpy.github.io/spring-addons/without-spring-addons/): the hand-written Spring Security equivalent of each auto-configured bean

The [samples](../samples) are runnable and use this starter in five different shapes.
