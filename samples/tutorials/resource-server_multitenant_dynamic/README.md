# How to configure a Spring REST API dynamic tenants
Sample of advanced customization of spring-addons auto-configuration.

There are two kinds of multi-tenancy we'll distinguish here:
- _Static_: all the trusted issuers are known before startup. `spring-addons-starter-oidc` supports this using application properties: `com.c4-soft.springaddons.oidc.ops` is an array where `ops` stands for **O**penID **P**rovider**s** (aka issuers). In this situation, we should define a group of properties for each OP, and the properties resolver will use the access token `iss` claim to match the property group to use when building the security context for a request.
- _Dynamic_: some OpenID Providers we should trust might be created after the Spring Relying Party started. A common use case are B2B system where a dedicated issuer is created for each company subscribing to the service. In such a situation, we cannot provide OPs configuration in application properties. `spring-addons-starter-oidc` addresses this by scanning the application context for an `OpenidProviderPropertiesResolver` in charge of resolving the OP configuration properties based on access token claims.

In this tutorial, we are interested in the _dynamic_ multi-tenancy.

The properties resolver we'll expose is designed to accept access tokens issued by any realm on a given Keycloak server.

Issuer URIs should look like `${keycloak-host}/realms/{realm-id}`.

We'll use the same configuration properties group for all realms, still, we want to make sure that only tokens issued by one of the realms of the unique Keycloak server we trust are accepted.

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that sources compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Prerequisites
We assume that [tutorials main README prerequisites section](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#prerequisites) has been achieved and that you have a minimum of 1 OIDC Provider (2 would be better) with ID and secret for clients configured with authorization-code flow.

## 2. Project Initialization
We'll be starting where the [`resource-server_with_oauthentication` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication) ends. Make sure you have this project running before you start.

## 3. Web-Security Configuration
As explained in the [`spring-addons-starter-oidc` README](), all we need is:
- defining the configuration to apply to all realms
```yaml
scheme: http
keycloak-port: 8080
keycloak-host: ${scheme}://localhost:${keycloak-port}

com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${keycloak-host}
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
```
- expose an `OpenidProviderPropertiesResolver` resolving this configuration properties from the token claims
```java
@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {

  @Component
  public class IssuerStartsWithOpenidProviderPropertiesResolver implements OpenidProviderPropertiesResolver {
    private final SpringAddonsOidcProperties properties;

    public IssuerStartsWithOpenidProviderPropertiesResolver(SpringAddonsOidcProperties properties) {
      this.properties = properties;
    }

    @Override
    public Optional<OpenidProviderProperties> resolve(Map<String, Object> claimSet) {
      final var tokenIss =
          Optional.ofNullable(claimSet.get(JwtClaimNames.ISS)).map(Object::toString)
              .orElseThrow(() -> new RuntimeException("Invalid token: missing issuer"));
      return properties.getOps().stream().filter(opProps -> {
        final var opBaseHref =
            Optional.ofNullable(opProps.getIss()).map(URI::toString).orElse(null);
        if (!StringUtils.hasText(opBaseHref)) {
          return false;
        }
        return tokenIss.startsWith(opBaseHref);
      }).findAny();
    }
  }
}
```
The `OpenidProviderPropertiesResolver` returns some `OpenidProviderProperties` only if the token `iss` claim starts with the value of the `iss` property in the configuration.

Note that we could have done something stricter with some pattern matching, but this implementation is enough for demonstration purposes.

## 5. Sample `@RestController`
No change, just keep the one from [`resource-server_with_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication)

## 5. Unit-Tests
No change, just keep the one from [`resource-server_with_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication)

## 6. Conclusion
Et voilà! We can now query our API with access tokens issued for any realm of our Keycloak instance (and got to see in action `spring-addons-starter-oidc` versatility)
