# Auto-configure `RestClient` or `WebClient` beans
This starter aims at auto-configuring `RestClient` and `WebClient` using application properties:
- requests authorization:
  - Bearer using a Spring Security OAuth2 client registration
  - Bearer re-using the access token in the security context of an `oauth2ResourceServer` request
  - static header value (API KEY)
  - Basic auth
- base path (property which can be overridden for each deployment)
- proxy auto-configuration using `HTTP_PROXY` and `NO_PROXY` environment variables (can be overridden or complemented with properties to, for instance, define credentials for the HTTP proxy)
- connection and read timeouts
- disable SSL certificates validation on a per-client basis
- choice of the `RestClient` underlying `ClientHttpRequestFactory`: 
  - `SimpleClientHttpRequestFactory` does not allow `PATCH` requests
  - `JdkClientHttpRequestFactory` is used by default, but it sets headers not supported by some Microsoft middleware
  - `HttpComponentsClientHttpRequestFactory` and `JettyClientHttpRequestFactory` require some additional jars on the classpath
- complete flexibility on the `RestClient`/`WebClient` beans configuration: a property allows exposing a pre-configured `Builder` instead of an already built instance to polish the configuration in Java code (use properties for the auto-configuration we're interested in and manually define just what isn't supported by the starter)
- supports many auto-configured `RestClient`/`WebClient` (or builders) beans

Instantiated REST clients are `WebClient` in WebFlux apps and `RestClient` in servlets, but any client can be switched to `WebClient` in servlets.

Exposed bean names are by default the `camelCase` transformation of the `kebab-case` key in the application properties map, with the `Builder` suffix when `expose-builder` is `true`. It can be set to anything else in properties.

There is no adherence to other `spring-addons` starters (`spring-addons-starter-rest` can be used without `spring-addons-starter-oidc`).

- [1. Important warning about bean names](#warning)
- [2. Usage](#usage)
  - [2.1. Dependency](#dependency)
  - [2.2. Minimal sample](#minimal-sample)
  - [2.3. Advanced configuration samples](#advanced-configuration)
  - [2.4. Defining `RestClient.Builder`/`WebClient.Builder` beans in Java code](#builder-in-java)
  - [2.5. Exposing a generated `@HttpExchange` proxy as a `@Bean`](#http-exchange-proxies)
  - [2.6. Changing the default `ClientHttpRequestFactory`](#client-http-request-factory)
  - [2.7. Working with SSL bundles](#ssl-bundles)
  - [2.8. Using `spring-addons-starter-rest` in a non-Web application](#non-web)

## <a name="warning">1. Important warning about bean names

By default the bean names are the camel-case transformation of the key in properties, with the `Builder` suffix if the `expose-builder` property is true. For instance:
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          foo-client:
            base-url: https://foo:8080
          bar-client:
            base-url: https://bar:8080
            expose-builder: true
```
would create beans named respectively `fooClient` and `barClientBuilder`.

`restClientBuilder` and `webClientBuilder` are the names of beans created by the "official" starter and used as a base by `spring-addons`. They should be considered as reserved bean names. **It is highly discouraged to use `rest-client` or `web-client` as key in `com.c4-soft.springaddons.rest.client` properties**. 

However, it is possible to discard Spring Boot defaults by exposing a `@Bean RestClient.Builder restClientBuilder() { ... }` or `@Bean WebClient.Builder webClientBuilder() { ... }`. `spring-addons` would use those as base for the beans it auto-configures instead of the beans exposed by the "official" starter).

## <a name="usage">2. Usage

To take the most value from the `RestClient`/`WebClient`, we may provide it to [`@HttpExchange` proxy factories](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest#exposing-a-generated-httpexchange-proxy-as-a-bean).

As a reminder, `@HttpExchange` interfaces describe a REST API from the client's point of view. The proxies mentioned above are generated implementations to consume this API. We can see it as a REST equivalent to what `@Repository` is for relational databases.

If the consumed REST API exposes an OpenAPI spec (using Swagger, maybe through [`springdoc-openapi`](https://springdoc.org/) and [Swagger annotations](https://github.com/swagger-api/swagger-core/wiki/Swagger-2.X---Annotations)), the `@HttpExchange` interfaces can be generated using the [`openapi-generator-maven-plugin`](https://github.com/OpenAPITools/openapi-generator/tree/master/modules/openapi-generator-maven-plugin) or [`openapi-generator-gradle-plugin`](https://github.com/OpenAPITools/openapi-generator/tree/master/modules/openapi-generator-gradle-plugin). 

In other words, we can consume REST APIs with almost zero boilerplate code:
1. generate the OpenAPI spec of REST APIs from their sources
2. generate the `@HttpExchange` interfaces describing how clients can consume these APIs from the OpenAPI specs
3. generate `@HttpExchange` proxies, providing each with a `RestClient`/`WebClient` bean auto-configured by `spring-addons-starter-rest`

The following describes the last point. Refer to the docs linked above to generate the OpenAPI spec from `@RestController` sources or to generate `@HttpExchange` from this spec.

### <a name="dependency">2.1. Dependency
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-rest</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
```

### <a name="minimal-sample" />2.2. Minimal sample
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

### <a name="advanced-configuration" />2.3. Advanced configuration samples
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
              # disable SSL certificates validation
              # when "client-http-request-factory-impl" is "jdk", only root authority validation is disabled (not the hostname, so the certificate CN or altnames must match the URL hostame)
              ssl-certificates-validation-enabled: false
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

### <a name="builder-in-java" />2.4. Defining `RestClient.Builder`/`WebClient.Builder` beans in Java code
`spring-addons-starter-rest` uses the `restClientBuilder` and `webClientBuilder` beans defined by the "official" Boot starter as base for the builders it auto-configures. 

But as these beans are `@ConditionalOnMissingBean`, defining a `RestClient.Builder` or `WebClient.Builder` in a `@Configuration` class disables the creation of these base beans and application code must provide a replacement. The following could be enough in many cases:
```java
// Expose a base builder for others. 
// The bean name is important: "restClientBuilder" ("webClientBuilder" in case of a WebClient.Builder)
@Bean
RestClient.Builder restClientBuilder() {
  // This is enough in many cases, but this default conf might be enhanced 
  // to use a specific ObjectMapper instance or whatever
  return RestClient.builder();
}

// Expose some builders as bean.
// Think twice, as in most cases, exposing the client is preferable to exposing its builder.
@Bean
RestClient.Builder fooClientBuilder(RestClient.Builder autoConfiguredBuilder) {
  return autoConfiguredBuilder.clone();
}
```

### <a name="http-exchange-proxies" />2.5. Exposing a generated `@HttpExchange` proxy as a `@Bean`
Once the REST clients are configured, we may use them to generate `@HttpExchange` implementations:
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

### <a name="client-http-request-factory" />2.6. Changing the default `ClientHttpRequestFactory`
If a `ClientHttpRequestFactory` bean is already configured in the application, `spring-addons-starter-rest` uses it for all auto-configured `RestClient` beans. Otherwise, it auto-configures one with:
- HTTP proxy if properties or `HTTP_PROXY` & `NO_PROXY` environment variables are set
- timeouts

The default implementation is `JdkClientHttpRequestFactory`. It can be switched to `HttpComponentsClientHttpRequestFactory` or `JettyClientHttpRequestFactory` using properties:
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

### <a name="ssl-bundles" />2.7. Working with SSL bundles
Let's consider the following Boot configurations for SSL with self-signed certificates generated with `openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt -sha256 -days 3650`:
- on the consumed REST API:
```yaml
server:
  ssl:
    bundle: server
spring:
  ssl:
    bundle:
      pem:
        server:
          keystore:
            certificate: classpath:tls.crt
            private-key: classpath:tls.key
            private-key-password: change-me
```
- on the service using a REST client to call the service above:
```yaml
spring:
  ssl:
    bundle:
      pem:
        client:
          truststore:
            certificate: classpath:tls.crt
com:
  c4-soft:
    springaddons:
      rest:
        client:
          machin-client:
            base-url: https://localhost:${machin-api-port}
            ssl-bundle: client
```
In the configuration above:
- The same (self-signed) certificate is used to configure a bundle named `server` on the consumed service, and another bundle named `client` the consuming side.
- The `server.ssl.bundle` property of the consumed service contains a reference of a bundle with a `keystore` (`spring.ssl.bundle.server`).
- The `com.c4-soft.springaddons.rest.client.{client-id}.ssl-bundle` property of the consuming service contains a reference of bundle with a `truststore` (`spring.ssl.bundle.client`).


### <a name="non-web" />2.8. Using `spring-addons-starter-rest` in a non-Web application

As `spring-boot-starter-oauth2-client` auto-configures only Web applications, we must import `OAuth2ClientProperties` and declare an `OAuth2AuthorizedClientManager` bean:
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

In the same way, `spring-addons-starter-rest` post-processes the bean definition registry to add definitions for `RestClient`/`WebClient` (or builders) beans of Web applications only. So, the following needs to be added to a servlet REST configuration for `RestClient` beans to be auto-configured:
```java
@Bean
SpringAddonsRestClientBeanDefinitionRegistryPostProcessor springAddonsRestClientBeanDefinitionRegistryPostProcessor(Environment environment) {
  return new SpringAddonsRestClientBeanDefinitionRegistryPostProcessor(environment);
}
```
To get `WebClient` beans, we should use `SpringAddonsServletWebClientBeanDefinitionRegistryPostProcessor` or `SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor`, depending on the application being synchronized or reactive.

When using `SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor`, we must expose a `ReactiveOAuth2AuthorizedClientManager` instead of an `OAuth2AuthorizedClientManager`.
