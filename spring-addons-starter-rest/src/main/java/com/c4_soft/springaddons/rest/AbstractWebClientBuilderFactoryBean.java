package com.c4_soft.springaddons.rest;

import java.net.URL;
import java.time.Duration;
import java.util.Optional;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.lang.Nullable;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.Builder;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.AuthorizationProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import io.netty.channel.ChannelOption;
import lombok.Setter;
import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.ProxyProvider;

/**
 * An abstraction of servlet and server (webflux) {@link FactoryBean} for {@link WebClient.Builder
 * WebClient Builder}.
 * 
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
@Setter
public abstract class AbstractWebClientBuilderFactoryBean
    implements FactoryBean<WebClient.Builder> {
  private String clientId;
  private SystemProxyProperties systemProxyProperties = new SystemProxyProperties();
  private SpringAddonsRestProperties restProperties = new SpringAddonsRestProperties();


  @Override
  @Nullable
  public WebClient.Builder getObject() throws Exception {
    final var builder = WebClient.builder();
    final var clientProps = Optional.ofNullable(restProperties.getClient().get(clientId))
        .orElseThrow(() -> new RestConfigurationNotFoundException(clientId));

    builder.clientConnector(clientConnector(systemProxyProperties, clientProps.getHttp()));

    clientProps.getBaseUrl().map(URL::toString).ifPresent(builder::baseUrl);

    setAuthorizationHeader(builder, clientProps.getAuthorization(), clientId);

    return builder;
  }

  @Override
  @Nullable
  public Class<?> getObjectType() {
    return WebClient.Builder.class;
  }

  public static ReactorClientHttpConnector clientConnector(
      SystemProxyProperties systemProxyProperties,
      ClientHttpRequestFactoryProperties addonsProperties) {

    final var client = HttpClient.create();

    addonsProperties.getConnectTimeoutMillis()
        .ifPresent(timeout -> client.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, timeout));
    addonsProperties.getReadTimeoutMillis()
        .ifPresent(timeout -> client.responseTimeout(Duration.ofMillis(timeout)));

    final var proxySupport = new ProxySupport(systemProxyProperties, addonsProperties.getProxy());
    if (proxySupport.isEnabled()) {
      client.proxy(proxy -> proxy.type(protocoleToProxyType(proxySupport.getProtocol()))
          .host(proxySupport.getHostname().get()).port(proxySupport.getPort())
          .username(proxySupport.getUsername()).password(username -> proxySupport.getPassword())
          .nonProxyHosts(proxySupport.getNoProxy())
          .connectTimeoutMillis(proxySupport.getConnectTimeoutMillis()));
    }

    return new ReactorClientHttpConnector(HttpClient.create());
  }

  static Optional<ReactorClientHttpConnector> httpConnector(ProxySupport proxySupport) {
    return proxySupport.getHostname().map(proxyHost -> {
      return new ReactorClientHttpConnector(HttpClient.create()
          .proxy(proxy -> proxy.type(protocoleToProxyType(proxySupport.getProtocol()))
              .host(proxyHost).port(proxySupport.getPort()).username(proxySupport.getUsername())
              .password(username -> proxySupport.getPassword())
              .nonProxyHosts(proxySupport.getNoProxy())
              .connectTimeoutMillis(proxySupport.getConnectTimeoutMillis())));

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

  protected void setAuthorizationHeader(WebClient.Builder clientBuilder,
      AuthorizationProperties authProps, String clientId) {
    if (authProps.getOauth2().isConfigured() && authProps.getBasic().isConfigured()) {
      throw new RestMisconfigurationException(
          "REST authorization configuration for %s can be made for either OAuth2 or Basic, but not both at a time"
              .formatted(clientId));
    }
    if (authProps.getOauth2().isConfigured()) {
      setBearerAuthorizationHeader(clientBuilder, authProps.getOauth2(), clientId);
    } else if (authProps.getBasic().isConfigured()) {
      setBasicAuthorizationHeader(clientBuilder, authProps.getBasic(), clientId);
    }
  }

  protected void setBearerAuthorizationHeader(WebClient.Builder clientBuilder,
      AuthorizationProperties.OAuth2Properties oauth2Props, String clientId) {
    if (!oauth2Props.isConfValid()) {
      throw new RestMisconfigurationException(
          "REST OAuth2 authorization configuration for %s can be made for either a registration-id or resource server Bearer forwarding, but not both at a time"
              .formatted(clientId));
    }
    if (oauth2Props.getOauth2RegistrationId().isPresent()) {
      clientBuilder
          .filter(registrationExchangeFilterFunction(oauth2Props.getOauth2RegistrationId().get()));
    } else if (oauth2Props.isForwardBearer()) {
      clientBuilder.filter(forwardingBearerExchangeFilterFunction());
    }
  }

  protected abstract ExchangeFilterFunction registrationExchangeFilterFunction(
      String Oauth2RegistrationId);

  protected abstract ExchangeFilterFunction forwardingBearerExchangeFilterFunction();

  protected void setBasicAuthorizationHeader(Builder clientBuilder,
      AuthorizationProperties.BasicAuthProperties authProps, String clientName) {
    if (authProps.getEncodedCredentials().isPresent()) {
      if (authProps.getUsername().isPresent() || authProps.getPassword().isPresent()
          || authProps.getCharset().isPresent()) {
        throw new RestMisconfigurationException(
            "REST Basic authorization for %s is misconfigured: when encoded-credentials is provided, username, password and charset must be absent."
                .formatted(clientName));
      }
    } else {
      if (authProps.getUsername().isEmpty() || authProps.getPassword().isEmpty()) {
        throw new RestMisconfigurationException(
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

}
