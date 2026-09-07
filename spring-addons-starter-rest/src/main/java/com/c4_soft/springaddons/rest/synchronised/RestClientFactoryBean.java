package com.c4_soft.springaddons.rest.synchronised;

import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;
import lombok.Setter;
import lombok.experimental.FieldNameConstants;

@Setter
@FieldNameConstants
public class RestClientFactoryBean implements FactoryBean<RestClient>, ApplicationContextAware {
  private String clientId;
  private SystemProxyProperties systemProxyProperties;
  private SpringAddonsRestProperties restProperties;
  private Optional<OAuth2AuthorizedClientManager> authorizedClientManager = Optional.empty();
  private Optional<ClientRegistrationRepository> clientRegistrationRepository = Optional.empty();
  private Optional<OAuth2AuthorizedClientRepository> authorizedClientRepository = Optional.empty();
  private Optional<ClientHttpRequestFactory> clientHttpRequestFactory;
  private Optional<ClientHttpRequestFactoryBuilder<?>> clientHttpRequestFactoryBuilder;
  private Optional<HttpClientSettings> httpClientSettings;
  private RestClient.Builder restClientBuilder;
  private @Nullable ApplicationContext applicationContext;

  @Override
  public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

  @Override
  @Nullable
  public RestClient getObject() throws Exception {
    final var builderFactoryBean = new RestClientBuilderFactoryBean();
    if (applicationContext != null) {
      builderFactoryBean.setApplicationContext(applicationContext);
    }
    builderFactoryBean.setClientId(clientId);
    builderFactoryBean.setSystemProxyProperties(systemProxyProperties);
    builderFactoryBean.setRestProperties(restProperties);
    builderFactoryBean.setAuthorizedClientManager(authorizedClientManager);
    builderFactoryBean.setClientRegistrationRepository(clientRegistrationRepository);
    builderFactoryBean.setAuthorizedClientRepository(authorizedClientRepository);
    builderFactoryBean.setClientHttpRequestFactory(clientHttpRequestFactory);
    builderFactoryBean.setClientHttpRequestFactoryBuilder(clientHttpRequestFactoryBuilder);
    builderFactoryBean.setHttpClientSettings(httpClientSettings);
    builderFactoryBean.setRestClientBuilder(restClientBuilder);
    return Optional.ofNullable(builderFactoryBean.getObject()).map(RestClient.Builder::build)
        .orElse(null);
  }

  @Override
  @Nullable
  public Class<?> getObjectType() {
    return RestClient.class;
  }
}
