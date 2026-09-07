package com.c4_soft.springaddons.rest.synchronised;

import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.http.client.reactive.ClientHttpConnectorBuilder;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;
import lombok.Setter;

@Setter
public class ServletWebClientFactoryBean implements FactoryBean<WebClient>, ApplicationContextAware {
  private String clientId;
  private SystemProxyProperties systemProxyProperties;
  private SpringAddonsRestProperties restProperties;
  private Optional<OAuth2AuthorizedClientManager> authorizedClientManager = Optional.empty();
  private Optional<ClientRegistrationRepository> clientRegistrationRepository = Optional.empty();
  private Optional<ClientHttpConnectorBuilder<?>> clientHttpConnectorBuilder;
  private Optional<HttpClientSettings> httpClientSettings;
  private WebClient.Builder webClientBuilder;
  private @Nullable ApplicationContext applicationContext;

  @Override
  public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

  @Override
  @Nullable
  public WebClient getObject() throws Exception {
    final var builderFactoryBean = new ServletWebClientBuilderFactoryBean();
    if (applicationContext != null) {
      builderFactoryBean.setApplicationContext(applicationContext);
    }
    builderFactoryBean.setClientId(clientId);
    builderFactoryBean.setSystemProxyProperties(systemProxyProperties);
    builderFactoryBean.setRestProperties(restProperties);
    builderFactoryBean.setAuthorizedClientManager(authorizedClientManager);
    builderFactoryBean.setClientRegistrationRepository(clientRegistrationRepository);
    builderFactoryBean.setClientHttpConnectorBuilder(clientHttpConnectorBuilder);
    builderFactoryBean.setHttpClientSettings(httpClientSettings);
    builderFactoryBean.setWebClientBuilder(webClientBuilder);
    return Optional.ofNullable(builderFactoryBean.getObject()).map(WebClient.Builder::build)
        .orElse(null);
  }

  @Override
  @Nullable
  public Class<?> getObjectType() {
    return WebClient.class;
  }
}
