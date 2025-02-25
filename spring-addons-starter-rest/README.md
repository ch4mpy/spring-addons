# Auto-configure `RestClient` or `WebClient` beans
This starter aims at auto-configuring `RestClient` and `WebClient` using application properties:
- base URL
- `Basic` or OAuth2 `Bearer` authorization; for the latter, using either a client registration or forwarding the access token in the security context of a resource server.
- proxy settings with consideration of `HTTP_PROXY` and `NO_PROXY` environment variables. Finer-grained configuration or overrides can be achieved with custom properties.
- connection and read timeouts
- headers with static values (for instance an API key)

Instantiated REST clients are `WebClient` in WebFlux apps and `RestClient` in servlets, but any client can be switched to `WebClient` in servlets.

Exposed bean names are by default the `camelCase` transformation of the `kebab-case` key in the application properties map, with the `Builder` suffix when `expose-builder` is `true`. It can be set to anything else in properties.

When the provided auto-configuration is not enough, it is possible to expose `RestClient.Builder` or `WebClient.Builder` instead of the already-built instances.

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
          # this exposes a bean named "machinClient"
          machin-client:
            # Easy to override in each deployment (for instance with COM_C4_SOFT_SPRINGADDONS_REST_CLIENT_MACHIN_CLIENT_BASE_URL environment variable)
            base-url: http://localhost:${machin-api-port
            http:
              connect-timeout-millis: 1000
              read-timeout-millis: 1000
              # requires org.apache.httpcomponents.client5:httpclient5 to be on the class-path
              client-http-request-factory-impl: http-components
              # Override what is defined in HTTP_PROXY and NO_PROXY environment variables
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
          # this exposes a bean named "biduleClientBuilder" (mind the "expose-builder: true" below)
          bidule-client:
            base-url: http://localhost:${bidule-api-port}
            # expose the RestClient.Builder instead of an already built RestClient.
            # The "Builder" suffix is added to the default bean name ("bidule-client" -> "biduleClient" -> "biduleClientBuilder" in this case)
            expose-builder: true
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
            # expose a WebClient instead of a RestClient in a servlet app
            type: WEB_CLIENT
            # change the bean name to "chose" (would be "choseClient" by default)
            bean-name: chose
            authorization:
              # authorize outgoing requests with Basic auth
              basic:
                username: spring-backend
                password: secret
            http:
              proxy:
                # Ignore HTTP_PROXY environment variable
                enabled: false
          chouette-client:
            base-url: https://something.pf/api
            # add headers with static values
            headers:
              X-API-KEY: change-me
              X-MULTI-VALUED-HEADER: 
              - foo
              - bar
              - bam
```
The `biduleClientBuilder` bean can be used to define a `biduleClient` bean as follows:
```java
/** 
 * @param biduleClientBuilder pre-configured using application properties
 * @return a {@link RestClient} bean named "biduleClient"
 */
@Bean
RestClient biduleClient(RestClient.Builder biduleClientBuilder) throws Exception {
  // Fine-tune biduleClientBuilder configuration
  return biduleClientBuilder.build();
}
```

## Exposing a generated `@HttpExchange` proxy as a `@Bean`
Once the REST clients are configured, we may use it to generate `@HttpExchange` implementations:
```java
/** 
 * @param machinClient pre-configured by spring-addons-starter-rest using application properties
 * @return a generated implementation of the {@link MachinApi} {@link HttpExchange &#64;HttpExchange}, exposed as a bean named "machinApi".
 */
@Bean
MachinApi machinApi(RestClient machinClient) throws Exception {
  return new RestClientHttpExchangeProxyFactoryBean<>(MachinApi.class, machinClient).getObject();
}

/** 
 * @param biduleClient the bean exposed just above
 * @return a generated implementation of the {@link BiduleApi} {@link HttpExchange &#64;HttpExchange}, exposed as a bean named "biduleApi".
 */
@Bean
BiduleApi biduleApi(RestClient biduleClient) throws Exception {
  return new RestClientHttpExchangeProxyFactoryBean<>(BiduleApi.class, biduleClient).getObject();
}
```

## Changing the default `ClientHttpRequestFactory`
If a `ClientHttpRequestFactory` bean is already configured in the application, `spring-addons-starter-rest` uses it for all auto-configured `RestClient` beans. Otherwise, it auto-configures one with:
- HTTP proxy if properties or `HTTP_PROXY` & `NO_PROXY` environment variables are set
- timeouts

The default implementation is `JdkClientHttpRequestFactory`. It can can be switched to `HttpComponentsClientHttpRequestFactory` or `JettyClientHttpRequestFactory` using properties:
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          machin-client:
            http:
              # requires org.apache.httpcomponents.client5:httpclient5 to be on the class-path
              client-http-request-factory-impl: http-components
          bidule-client:
            http:
              # requires org.eclipse.jetty:jetty-client to be on the class-path
              client-http-request-factory-impl: jetty
```

## Using `spring-addons-starter-rest` in a non-Web application
Most auto-configuration is turned off (both from `spring-addons-starter-rest` and `spring-boot-starter-oauth2-client`).

`spring-boot-starter-oauth2-client` auto-configures only Web application. So we need first to import `OAuth2ClientProperties` and declare an `OAuth2AuthorizedClientManager` bean:
```java
@Configuration
@Import(OAuth2ClientProperties.class)
public class SecurityConfiguration {

  @Bean
  ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties properties) {
    List<ClientRegistration> registrations = new ArrayList<>(
        new OAuth2ClientPropertiesMapper(properties).asClientRegistrations().values());
    return new InMemoryClientRegistrationRepository(registrations);
  }

  @Bean
  OAuth2AuthorizedClientService authorizedClientService(
      ClientRegistrationRepository clientRegistrationRepository) {
    return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
  }

  @Bean
  OAuth2AuthorizedClientManager authorizedClientManager(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientService authorizedClientService) {
    return new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository,
        authorizedClientService);
  }
}
```

In the same way, `spring-addons-starter-rest` post-processes the bean definition registry to add definitions for `RestClient`/`WebClient` (or builders) beans of Web application only. So, the following needs to be added to a servlet REST configuration for `RestClient` beans to be auto-configured:
```java
@Bean
SpringAddonsRestClientBeanDefinitionRegistryPostProcessor springAddonsRestClientBeanDefinitionRegistryPostProcessor(Environment environment) {
  return new SpringAddonsRestClientBeanDefinitionRegistryPostProcessor(environment);
}
```
To get `WebClient` beans, we should use `SpringAddonsServletWebClientBeanDefinitionRegistryPostProcessor` or `SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor` depending on the application being synchronized or reactive.
