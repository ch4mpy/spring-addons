---
title: spring-addons-starter-rest
nav_order: 5
has_children: true
description: "Auto-configure RestClient and WebClient beans from properties: Bearer and Basic authorization, API keys, base URL, HTTP proxies, timeouts, SSL bundles and the underlying HTTP client library."
---

# `spring-addons-starter-rest`
{: .no_toc }

This starter aims at auto-configuring `RestClient` and `WebClient` using application properties:

- requests authorization:
  - Bearer using a Spring Security OAuth2 client registration
  - Bearer re-using the access token in the security context of an `oauth2ResourceServer` request
  - static header value (API KEY)
  - Basic auth
- base path (property which can be overridden for each deployment)
- proxy auto-configuration using `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` environment variables (`HTTPS_PROXY` applies to `https://` targets and `HTTP_PROXY` to `http://` ones, each falling back to the other; `NO_PROXY` supports `*` wildcards and leading-dot domains). Can be overridden or complemented with properties to, for instance, define credentials for the HTTP proxy
- connection and read timeouts
- disable SSL certificates validation on a per client basis
- choice of the `RestClient` underlying `ClientHttpRequestFactory`:
  - `SimpleClientHttpRequestFactory` does not allow `PATCH` requests
  - `JdkClientHttpRequestFactory` is used by default, but it sets headers not supported by some Microsoft middleware
  - `HttpComponentsClientHttpRequestFactory` and `JettyClientHttpRequestFactory` require some additional jars on the classpath
- complete flexibility on the `RestClient`/`WebClient` beans configuration: a property allows exposing a pre-configured `Builder` instead of an already built instance to polish the configuration in Java code (use properties for the auto-configuration we're interested in and manually define just what isn't supported by the starter)
- supports many auto-configured `RestClient`/`WebClient` (or builders) beans

Instantiated REST clients are `WebClient` in WebFlux apps and `RestClient` in servlets, but any client can be switched to `WebClient` in servlets.

There is no adherence to other `spring-addons` starters: `spring-addons-starter-rest` can be used without `spring-addons-starter-oidc`, and [outside a web application]({{ site.baseurl }}/rest/non-web/).

## Important warning about bean names

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

`restClientBuilder` and `webClientBuilder` being the name of beans created by the "official" starter and used as base by `spring-addons`, they should be considered as reserved bean names. **It is highly discouraged to use `rest-client` or `web-client` as key in `com.c4-soft.springaddons.rest.client` properties**.

However, it is possible to discard Spring Boot defaults by exposing a `@Bean RestClient.Builder restClientBuilder() { ... }` or `@Bean WebClient.Builder webClientBuilder() { ... }`. `spring-addons` would use those as base for the beans it auto-configures instead of the beans exposed by the "official" starter.

## Where to go next

- [Usage]({{ site.baseurl }}/rest/usage/): the dependency, a minimal sample, the advanced configuration samples, and backing `@ImportHttpServices` groups with an auto-configured client.
- [HTTP client and proxies]({{ site.baseurl }}/rest/request-factories/): changing the `ClientHttpRequestFactory`, timeouts, and proxies.
- [SSL bundles]({{ site.baseurl }}/rest/ssl-bundles/): self-signed certificates and development shortcuts.
- [Non-web applications]({{ site.baseurl }}/rest/non-web/).
