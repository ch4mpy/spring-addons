# Auto-configure `RestClient` or `WebClient` beans
This starter aims at auto-configuring `RestClient` and `WebClient` using application properties:
- base URL
- `Basic` or OAuth2 `Bearer` authorization; for the latter, using either a client registration or forwarding the access token in the security context of a resource server.
- proxy settings with consideration of `HTTP_PROXY` and `NO_PROXY` environment variables. Finer-grained configuration or overrides can be achieved with custom properties.
- connection and read timeouts

Instantiated REST clients are `WebClient` in WebFlux apps and `RestClient` in servlets, but any client can be switched to `WebClient` in servlets.

Exposed bean names are by default the `camelCase` transformation of the `kebab-case` key in the application properties map, with the `Builder` suffix when `expose-builder` is `true`. It can be set to anything else in properties.

When more is needed than the provided auto-configuration, it is possible to expose `RestClient.Builder` or `WebClient.Builder` instead of the already built instances.

There is no adherence to other `spring-addons` starters (`spring-addons-starter-rest` can be used without `spring-addons-starter-oidc`).

## Dependency
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starters-rest</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
```

### Minimal sample
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          keycloak-admin-client:
            base-url: ${keycloak-base-uri}/admin/realms
            authorization:
              oauth2:
                forward-bearer: true
```
This exposes a pre-configured bean named `keycloakAdminClient`. The default type of this bean is `RestClient` in a servlet app and `WebClient` in a Webflux one.

## Advanced configuration samples
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          machin-client:
            base-url: http://localhost:${machin-api-port}
            # expose a WebClient instead of a RestClient in a servlet app
            type: WEB_CLIENT
            # expose the WebClient.Builder instead of an already built WebClient
            expose-builder: true
            http:
              chunk-size: 1000
              connect-timeout-millis: 1000
              read-timeout-millis: 1000
              proxy:
                connect-timeout-millis: 500
                enabled: true
                host: proxy2.corporate.pf
                non-proxy-hosts-pattern: .+\.corporate\.pf
                username: spring-backend
                password: secret
                port: 8080
                protocol: http
            authorization:
              oauth2:
                # authorize outgoing requests with the Bearer token in the security (possible only in a resource server app)
                forward-bearer: true
          bidule-client:
            base-url: http://localhost:${bidule-api-port}
            authorization:
              oauth2:
                # authorize outgoing requests with a Bearer obtained using an OAuth2 client registration
                oauth2-registration-id: bidule-registration
            http:
              proxy:
                # use HTTP_PROXY and NO_PROXY environment variables and add proxy authentication
                username: spring-backend
                password: secret
          chose-client:
            base-url: http://localhost:${chose-api-port}
            # change the bean name to "chose" (default would have bean "choseClient" because of the "chose-client" ID, or "choseClientBuilder" if expose-builder was true)
            bean-name: chose
            authorization:
              # authorize outgoing requests with Basic auth
              basic:
                username: spring-backend
                password: secret
            http:
              proxy:
                enabled: false
```
The builder for the first client can be used as follows:
```java
@Configuration
public class RestConfiguration {
  @Bean
  WebClient machinClient(WebClient.Builder machinClientBuilder) throws Exception {
    // Add some configuration to the machinClientBuilder
    return machinClientBuilder.build();
  }
}
```

## Exposing a generated `@HttpExchange` proxy as a `@Bean`
Once the REST clients configured, we may use it to generate `@HttpExchange` implementations:
```java
@Configuration
public class RestConfiguration {
  /** 
   * @param machinClient might be auto-configured by spring-addons-starter-rest or a hand-crafted bean
   * @return a generated implementation of the {@link MachinApi} {@link HttpExchange &#64;HttpExchange}, exposed as a bean named "machinApi".
   */
  @Bean
  MachinApi machinApi(RestClient machinClient) throws Exception {
    return new RestClientHttpExchangeProxyFactoryBean<>(MachinApi.class, machinClient).getObject();
  }
}
```