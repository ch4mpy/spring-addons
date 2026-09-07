package com.c4_soft.springaddons.rest;

import java.net.URL;
import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.http.client.reactive.ClientHttpConnectorBuilder;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.Builder;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.AuthorizationProperties;
import lombok.Setter;
import lombok.experimental.FieldNameConstants;

/**
 * An abstraction of servlet and server (webflux) {@link FactoryBean} for {@link WebClient.Builder
 * WebClient Builder}.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Setter
@FieldNameConstants
public abstract class AbstractWebClientBuilderFactoryBean
    implements FactoryBean<WebClient.Builder>, ApplicationContextAware {
  private String clientId;
  private SystemProxyProperties systemProxyProperties = new SystemProxyProperties();
  private SpringAddonsRestProperties restProperties = new SpringAddonsRestProperties();
  private WebClient.Builder webClientBuilder;
  private Optional<ClientHttpConnectorBuilder<?>> clientHttpConnectorBuilder;
  private Optional<HttpClientSettings> httpClientSettings;
  private @Nullable ApplicationContext applicationContext;

  @Override
  public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

  private SslBundle resolveSslBundle(String bundleName) {
    if (applicationContext == null) {
      throw new RestMisconfigurationException(
          "ssl-bundle requires an ApplicationContext to resolve the '%s' bundle for REST client '%s'"
              .formatted(bundleName, clientId));
    }
    return applicationContext.getBean(SslBundles.class).getBundle(bundleName);
  }

  @Override
  public WebClient.Builder getObject() throws Exception {
    return configure(webClientBuilder.clone());
  }

  /**
   * Applies this factory bean's client-id configuration (connector, base URL, authorization,
   * headers) onto the given builder, instead of a fresh {@code webClientBuilder} clone. Used to
   * back {@code @ImportHttpServices} groups with the same configuration as the client-id's own
   * bean.
   */
  public WebClient.Builder configure(WebClient.Builder builder) {
    final var clientProps = Optional.ofNullable(restProperties.getClient().get(clientId))
        .orElseThrow(() -> new RestConfigurationNotFoundException(clientId));
    final var http = clientProps.getHttp();

    // Reuse or enrich the context ClientHttpConnectorBuilder / ClientHttpConnector with
    // spring-addons customization (proxy, timeouts, SSL), never mutating the context beans.
    builder.clientConnector(ClientHttpConnectorMerger.merge(clientId, systemProxyProperties, http,
        clientProps.getSslBundle(), clientProps.getSslBundle().map(this::resolveSslBundle),
        clientHttpConnectorBuilder, httpClientSettings));

    clientProps.getBaseUrl().map(URL::toString).ifPresent(builder::baseUrl);

    setAuthorizationHeader(builder, clientProps.getAuthorization(), clientId);

    for (var header : clientProps.getHeaders().entrySet()) {
      builder.defaultHeader(header.getKey(),
          header.getValue().toArray(new String[header.getValue().size()]));
    }

    return builder;
  }

  @Override
  @Nullable
  public Class<?> getObjectType() {
    return WebClient.Builder.class;
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
