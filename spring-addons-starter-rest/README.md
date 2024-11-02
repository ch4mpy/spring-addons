# Auto-configure `RestClient` or `WebClient`, ease `@HttpExchange` proxies generation
This starter aims at auto-configuring `RestClient` and `WebClient`. For now, it supports:
- base URL
- `Basic` or OAuth2 `Bearer` authorization; for the latter, using either a client registration or forwarding the access token in the security context of a resource server.
- proxy settings with consideration of `HTTP_PROXY` and `NO_PROXY` environment variables. Finer-grained configuration or overrides can be achieved with custom properties.
- connection and read timeouts
- instantiate `RestClient` in servlets and `WebClient` in WebFlux apps. Any client can be switched to `WebClient` in servlets.
- client bean names are by default the camelCase transformation of the key in the application properties map, with the `Builder` suffix when `expose-builder` is true. It can be set to anything else in properties.

When more is needed than what can be auto-configured, it is possible to have `RestClient.Builder` or `WebClient.Builder` exposed as beans instead of the already built instances.

## Usage since `8.0.0-RC1`
### Dependency
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
The `keycloakAdminClient` bean can be autowired in any `@Component` or `@Configuration`. For instance when generating an `@HttpExchange` proxy:
```java
@Configuration
public class RestConfiguration {
  @Bean
  KeycloakAdminApi keycloakAdminApi(RestClient keycloakAdminClient) throws Exception {
    return new RestClientHttpExchangeProxyFactoryBean<>(KeycloakAdminApi.class, keycloakAdminClient).getObject();
  }
}
```

### Advanced configuration sample for 3 different clients
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          machin-client:
            base-url: http://localhost:${machin-api-port}
            expose-builder: true
            type: WEB_CLIENT
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
                forward-bearer: true
          bidule-client:
            base-url: http://localhost:${bidule-api-port}
            authorization:
              oauth2:
                oauth2-registration-id: bidule-registration
            http:
              proxy:
                # Use HTTP_PROXY and NO_PROXY environment variables
                username: spring-backend
                password: secret
          chose-client:
            base-url: http://localhost:${chose-api-port}
            bean-name: chose
            authorization:
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
  RestClient machinClient(RestClient.Builder machinClientBuilder) throws Exception {
    // Add some configuration to the machinClientBuilder
    return machinClientBuilder.build();
  }
}
```
