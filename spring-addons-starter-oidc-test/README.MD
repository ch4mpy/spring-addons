# Unit & Integration Testing Applications Using `spring-addons-starter-oidc`

`spring-addons-starter-oidc-test` builds on top of [`spring-addons-oauth2-test`](../spring-addons-oauth2-test) and adds:

- annotations to apply `spring-addons-starter-oidc` auto-configuration to tests security-context
- thin wrappers around `MockMvc` and `WebTestClient` which make tests requests even easier

```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc-test</artifactId>
    <version>${springaddons.version}</version>
    <scope>test</scope>
</dependency>
```

## Documentation

- [Test slices](https://ch4mpy.github.io/spring-addons/testing/slices/): `@AutoConfigureAddons*`, `MockMvcSupport` and `WebTestClientSupport`
- [Annotations](https://ch4mpy.github.io/spring-addons/testing/annotations/)
- [Testing access control](https://ch4mpy.github.io/spring-addons/testing/), and why the authentication converter of the application has to run in tests too
