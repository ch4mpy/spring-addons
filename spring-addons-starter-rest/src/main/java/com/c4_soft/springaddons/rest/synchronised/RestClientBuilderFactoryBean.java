package com.c4_soft.springaddons.rest.synchronised;

import java.net.URL;
import java.util.Optional;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.boot.autoconfigure.web.client.RestClientSsl;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.lang.Nullable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.rest.RestConfigurationNotFoundException;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.AuthorizationProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;
import lombok.Data;
import lombok.experimental.FieldNameConstants;

@Data
@FieldNameConstants
public class RestClientBuilderFactoryBean implements FactoryBean<RestClient.Builder> {
  private String clientId;
  private SystemProxyProperties systemProxyProperties = new SystemProxyProperties();
  private SpringAddonsRestProperties restProperties = new SpringAddonsRestProperties();
  private Optional<OAuth2AuthorizedClientManager> authorizedClientManager;
  private Optional<ClientRegistrationRepository> clientRegistrationRepository;
  private Optional<OAuth2AuthorizedClientRepository> authorizedClientRepository;
  private Optional<ClientHttpRequestFactory> clientHttpRequestFactory;
  private RestClient.Builder restClientBuilder = RestClient.builder();
  private Optional<RestClientSsl> ssl;


  @Override
  @Nullable
  public RestClient.Builder getObject() throws Exception {
    final var clientProps = Optional.ofNullable(restProperties.getClient().get(clientId))
        .orElseThrow(() -> new RestConfigurationNotFoundException(clientId));

    final var builder = restClientBuilder.clone();

    // Handle HTTP or SOCK proxy and set timeouts
    builder.requestFactory(clientHttpRequestFactory
        .orElseGet(() -> new SpringAddonsClientHttpRequestFactory(systemProxyProperties,
            clientProps.getHttp())));

    clientProps.getBaseUrl().map(URL::toString).ifPresent(builder::baseUrl);

    setAuthorizationHeader(builder, clientProps.getAuthorization(), clientId);

    for (var header : clientProps.getHeaders().entrySet()) {
      builder.defaultHeader(header.getKey(),
          header.getValue().toArray(new String[header.getValue().size()]));
    }

    clientProps.getSslBundle()
        .ifPresent(sslBundle -> builder.apply(ssl.get().fromBundle(sslBundle)));

    return builder;
  }

  @Override
  @Nullable
  public Class<?> getObjectType() {
    return RestClient.Builder.class;
  }

  protected void setAuthorizationHeader(RestClient.Builder clientBuilder,
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

  protected void setBearerAuthorizationHeader(RestClient.Builder clientBuilder,
      AuthorizationProperties.OAuth2Properties oauth2Props, String clientId) {
    if (!oauth2Props.isConfValid()) {
      throw new RestMisconfigurationException(
          "REST OAuth2 authorization configuration for %s can be made for either a registration-id or resource server Bearer forwarding, but not both at a time"
              .formatted(clientId));
    }
    if (oauth2Props.getOauth2RegistrationId().isPresent()) {
      clientBuilder.requestInterceptor(
          registrationClientHttpRequestInterceptor(oauth2Props.getOauth2RegistrationId().get()));
    } else if (oauth2Props.isForwardBearer()) {
      clientBuilder.requestInterceptor(forwardingClientHttpRequestInterceptor());
    }
  }

  protected ClientHttpRequestInterceptor forwardingClientHttpRequestInterceptor() {
    return (HttpRequest request, byte[] body, ClientHttpRequestExecution execution) -> {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      if (auth != null && auth.getPrincipal() instanceof OAuth2Token oauth2Token) {
        request.getHeaders().setBearerAuth(oauth2Token.getTokenValue());
      }
      return execution.execute(request, body);
    };
  }

  protected ClientHttpRequestInterceptor registrationClientHttpRequestInterceptor(
      String registrationId) {
    if (authorizedClientManager.isEmpty()) {
      throw new RestMisconfigurationException(
          "OAuth2 client missconfiguration. Can't setup an OAuth2 Bearer request interceptor because there is no OAuth2AuthorizedClientManager bean.");
    }
    if (clientRegistrationRepository.isEmpty()) {
      throw new RestMisconfigurationException(
          "OAuth2 client missconfiguration. Can't setup an OAuth2 Bearer request interceptor because there is no ClientRegistrationRepository bean.");
    }

    final var registration =
        clientRegistrationRepository.get().findByRegistrationId(registrationId);
    if (registration == null) {
      throw new RestMisconfigurationException(
          "OAuth2 client missconfiguration. %s is not a known OAuth2 client registration"
              .formatted(registrationId));
    }

    final var interceptor = new OAuth2ClientHttpRequestInterceptor(authorizedClientManager.get());
    interceptor.setClientRegistrationIdResolver((HttpRequest request) -> registrationId);
    authorizedClientRepository.map(OAuth2ClientHttpRequestInterceptor::authorizationFailureHandler)
        .ifPresent(interceptor::setAuthorizationFailureHandler);
    if (AuthorizationGrantType.CLIENT_CREDENTIALS
        .equals(registration.getAuthorizationGrantType())) {
      interceptor.setPrincipalResolver(request -> null);
    }
    return interceptor;
  }

  protected void setBasicAuthorizationHeader(RestClient.Builder clientBuilder,
      AuthorizationProperties.BasicAuthProperties authProps, String clientId) {
    if (authProps.getEncodedCredentials().isPresent()) {
      if (authProps.getUsername().isPresent() || authProps.getPassword().isPresent()
          || authProps.getCharset().isPresent()) {
        throw new RestMisconfigurationException(
            "REST Basic authorization for %s is misconfigured: when encoded-credentials is provided, username, password and charset must be absent."
                .formatted(clientId));
      }
    } else {
      if (authProps.getUsername().isEmpty() || authProps.getPassword().isEmpty()) {
        throw new RestMisconfigurationException(
            "REST Basic authorization for %s is misconfigured: when encoded-credentials is empty, username & password are required."
                .formatted(clientId));
      }
    }
    clientBuilder.requestInterceptor((request, body, execution) -> {
      authProps.getEncodedCredentials().ifPresent(request.getHeaders()::setBasicAuth);
      authProps.getCharset().ifPresentOrElse(
          charset -> request.getHeaders().setBasicAuth(authProps.getUsername().get(),
              authProps.getPassword().get(), charset),
          () -> request.getHeaders().setBasicAuth(authProps.getUsername().get(),
              authProps.getPassword().get()));
      return execution.execute(request, body);
    });
  }

}
