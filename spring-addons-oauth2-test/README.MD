# Unit & Integration Testing With Security

Testing method security (`@PreAuthorize`, `@PostFilter`, etc.) requires to configure the security context. `Spring-security-test` provides with `MockMvc` request post-processors and `WebTestClient` mutators to do so, but this requires the context of a request, which limits its usage to testing secured controllers.

To test method security on any type of `@Component` (`@Controller`, off course, but also `@Service` and `@Repository`) there are only two options: build tests security context by yourself and populate it with stubbed / mocked authentications, or use annotations to do it for you. **This lib contains annotations to configure test security context with OAuth2 authentication at your hand.**

```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-oauth2-test</artifactId>
    <version>${springaddons.version}</version>
    <scope>test</scope>
</dependency>
```

`@WithMockAuthentication` covers role-based access control. When access control needs claim-set details, `@WithJwt` and `@WithOpaqueToken` build the `Authentication` from a JSON payload on the classpath **and the authentication converter in the context**, and `@WithOAuth2Login` and `@WithOidcLogin` do the same for a client with `oauth2Login`.

## Documentation

- [Annotations reference](https://ch4mpy.github.io/spring-addons/testing/annotations/), including the warning about what `spring-security-test` post-processors and mutators skip
- [Testing access control](https://ch4mpy.github.io/spring-addons/testing/), the overview
- [Test slices](https://ch4mpy.github.io/spring-addons/testing/slices/) for applications using `spring-addons-starter-oidc`
- The Baeldung article [Testing access control with mocked OAuth2 authentications](https://www.baeldung.com/spring-oauth-testing-access-control)

Every module of the [samples](../samples) tests its access control with these annotations.
