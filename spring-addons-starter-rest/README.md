# spring-addons-starter-rest

Auto-configures `RestClient` and `WebClient` beans from application properties: requests authorization (Bearer from a client registration, Bearer forwarded from the security context, API key header, Basic auth), base URL, HTTP proxies from the `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` environment variables, connection and read timeouts, SSL bundles, and the choice of the underlying `ClientHttpRequestFactory`.

```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-rest</artifactId>
    <version>${springaddons.version}</version>
</dependency>
```

```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          # exposes a RestClient bean named machinClient (a WebClient in a reactive app)
          machin-client:
            base-url: ${machin-api}
            authorization:
              oauth2:
                forward-bearer: true
```

Instantiated REST clients are `WebClient` in WebFlux apps and `RestClient` in servlets, but any client can be switched to `WebClient` in servlets. There is no adherence to the other `spring-addons` starters, and this one works outside a web application too.

## Documentation

- [Overview and bean naming rules](https://ch4mpy.github.io/spring-addons/rest/), including the reserved `restClientBuilder` and `webClientBuilder` names
- [Usage](https://ch4mpy.github.io/spring-addons/rest/usage/): minimal and advanced samples, and backing `@ImportHttpServices` groups with an auto-configured client
- [HTTP client and proxies](https://ch4mpy.github.io/spring-addons/rest/request-factories/)
- [SSL bundles](https://ch4mpy.github.io/spring-addons/rest/ssl-bundles/)
- [Non-web applications](https://ch4mpy.github.io/spring-addons/rest/non-web/)

The [`rest-client`](../samples/rest-client) sample is a runnable application using all of it.
