package com.c4_soft.springaddons.rest;

import java.net.URL;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.Builder;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.AuthorizationProperties;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.ProxyProvider;

/**
 * @author Jerome Wacongne chl4mp&#64;c4-soft.com
 */
public abstract class AbstractSpringAddonsWebClientSupport {

  private final ProxySupport proxySupport;

  private final Map<String, SpringAddonsRestProperties.RestClientProperties> restClientProperties;

  /**
   * A {@link BearerProvider} to get the Bearer from the request security context
   */
  private final Optional<ReactiveBearerProvider> bearerProvider;

  public AbstractSpringAddonsWebClientSupport(SystemProxyProperties systemProxyProperties,
      SpringAddonsRestProperties addonsRestProperties,
      Optional<ReactiveBearerProvider> bearerProvider) {
    super();
    this.proxySupport = new ProxySupport(systemProxyProperties, addonsRestProperties);
    this.restClientProperties = addonsRestProperties.getClient();
    this.bearerProvider = bearerProvider;
  }

  public WebClient.Builder client() {
    final var clientBuilder = WebClient.builder();

    httpConnector(proxySupport).ifPresent(clientBuilder::clientConnector);

    return clientBuilder;
  }

  /**
   * @param clientName key in "com.c4-soft.springaddons.rest.client" entries of
   *        {@link SpringAddonsRestProperties}
   * @return A {@link WebClient} Builder pre-configured with a base-URI and (optionally) with a
   *         Bearer Authorization
   */
  public WebClient.Builder client(String clientName) {
    final var clientProps = Optional.ofNullable(restClientProperties.get(clientName))
        .orElseThrow(() -> new RestConfigurationNotFoundException(clientName));

    final var clientBuilder = client();

    clientProps.getBaseUrl().map(URL::toString).ifPresent(clientBuilder::baseUrl);

    authorize(clientBuilder, clientProps.getAuthorization(), clientName);

    return clientBuilder;
  }

  /**
   * Uses the provided {@link WebClient} to proxy the httpServiceClass
   *
   * @param <T>
   * @param client
   * @param httpServiceClass class of the #64;Service (with {@link HttpExchange} methods) to proxy
   *        with a {@link WebClient}
   * @return a #64;Service proxy with a {@link WebClient}
   */
  public <T> T service(WebClient client, Class<T> httpServiceClass) {
    return HttpServiceProxyFactory.builderFor(WebClientAdapter.create(client)).build()
        .createClient(httpServiceClass);
  }

  /**
   * Builds a {@link WebClient} with just the provided spring-addons
   * {@link SpringAddonsRestProperties} and uses it to proxy the httpServiceClass.
   *
   * @param <T>
   * @param httpServiceClass class of the #64;Service (with {@link HttpExchange} methods) to proxy
   *        with a {@link WebClient}
   * @param clientName key in "rest" entries of spring-addons client properties
   * @return a #64;Service proxy with a {@link WebClient}
   */
  public <T> T service(String clientName, Class<T> httpServiceClass) {
    return this.service(this.client(clientName).build(), httpServiceClass);
  }

  protected Optional<ReactorClientHttpConnector> httpConnector(ProxySupport proxySupport) {
    return proxySupport.getHostname().map(proxyHost -> {
      return new ReactorClientHttpConnector(HttpClient.create()
          .proxy(proxy -> proxy.type(protocoleToProxyType(proxySupport.getProtocol()))
              .host(proxyHost).port(proxySupport.getPort()).username(proxySupport.getUsername())
              .password(username -> proxySupport.getPassword())
              .nonProxyHosts(proxySupport.getNoProxy())
              .connectTimeoutMillis(proxySupport.getConnectTimeoutMillis())));

    });
  }

  protected void authorize(Builder clientBuilder, AuthorizationProperties authProps,
      String clientName) {
    if (authProps.getOauth2().isConfigured() && authProps.getBasic().isConfigured()) {
      throw new RestMisconfigurationConfigurationException(
          "REST authorization configuration for %s can be made for either OAuth2 or Basic, but not both at a time"
              .formatted(clientName));
    }
    if (authProps.getOauth2().isConfigured()) {
      oauth2(clientBuilder, authProps.getOauth2(), clientName);
    }
    if (authProps.getBasic().isConfigured()) {
      basic(clientBuilder, authProps.getBasic(), clientName);
    }
  }

  protected void oauth2(Builder clientBuilder, AuthorizationProperties.OAuth2Properties oauth2Props,
      String clientName) {
    if (!oauth2Props.isConfValid()) {
      throw new RestMisconfigurationConfigurationException(
          "REST OAuth2 authorization configuration for %s can be made for either a registration-id or resource server Bearer forwarding, but not both at a time"
              .formatted(clientName));
    }
    oauth2Props.getOauth2RegistrationId().map(this::oauth2RegistrationFilter)
        .ifPresent(clientBuilder::filter);
    if (oauth2Props.isForwardBearer()) {
      clientBuilder.filter((ClientRequest request, ExchangeFunction next) -> {
        final Mono<ClientRequest> clientRequest = Mono.justOrEmpty(bearerProvider)
            .flatMap(provider -> provider.getBearer(request)).map(bearer -> {
              final var modified = ClientRequest.from(request);
              modified.headers(headers -> headers.setBearerAuth(bearer));
              return modified.build();
            }).defaultIfEmpty(request);
        return clientRequest.flatMap(next::exchange);
      });
    }
  }

  protected abstract ExchangeFilterFunction oauth2RegistrationFilter(String registrationId);

  protected void basic(Builder clientBuilder, AuthorizationProperties.BasicAuthProperties authProps,
      String clientName) {
    if (authProps.getEncodedCredentials().isPresent()) {
      if (authProps.getUsername().isPresent() || authProps.getPassword().isPresent()
          || authProps.getCharset().isPresent()) {
        throw new RestMisconfigurationConfigurationException(
            "REST Basic authorization for %s is misconfigured: when encoded-credentials is provided, username, password and charset must be absent."
                .formatted(clientName));
      }
    } else {
      if (authProps.getUsername().isEmpty() || authProps.getPassword().isEmpty()) {
        throw new RestMisconfigurationConfigurationException(
            "REST Basic authorization for %s is misconfigured: when encoded-credentials is empty, username & password are required."
                .formatted(clientName));
      }
    }
    clientBuilder.filter((ClientRequest request, ExchangeFunction next) -> {
      if (authProps.getEncodedCredentials().isEmpty() && authProps.getUsername().isEmpty()) {
        return next.exchange(request);
      }
      final var modified = ClientRequest.from(request);
      if (authProps.getEncodedCredentials().isPresent()) {
        modified.headers(headers -> headers.setBasicAuth(authProps.getEncodedCredentials().get()));
      } else if (authProps.getCharset().isPresent()) {
        modified.headers(headers -> headers.setBasicAuth(authProps.getUsername().get(),
            authProps.getPassword().get(), authProps.getCharset().get()));
      } else {
        modified.headers(headers -> headers.setBasicAuth(authProps.getUsername().get(),
            authProps.getPassword().get()));
      }
      return next.exchange(modified.build());

    });
  }

  static ProxyProvider.Proxy protocoleToProxyType(String protocol) {
    if (protocol == null) {
      return null;
    }
    final var lower = protocol.toLowerCase();
    if (lower.startsWith("http")) {
      return ProxyProvider.Proxy.HTTP;
    }
    if (lower.startsWith("socks4")) {
      return ProxyProvider.Proxy.SOCKS4;
    }
    return ProxyProvider.Proxy.SOCKS5;
  }
}
