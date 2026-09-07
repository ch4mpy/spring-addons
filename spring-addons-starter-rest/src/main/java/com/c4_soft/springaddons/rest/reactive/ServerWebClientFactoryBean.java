package com.c4_soft.springaddons.rest.reactive;

import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.http.client.reactive.ClientHttpConnectorBuilder;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;
import lombok.Setter;
import lombok.experimental.FieldNameConstants;

@Setter
@FieldNameConstants
public class ServerWebClientFactoryBean implements FactoryBean<WebClient>, ApplicationContextAware {
  private String clientId;
  private SystemProxyProperties systemProxyProperties;
  private SpringAddonsRestProperties restProperties;
  private Optional<ReactiveOAuth2AuthorizedClientManager> authorizedClientManager =
      Optional.empty();
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
    final var builderFactoryBean = new ServerWebClientBuilderFactoryBean();
    if (applicationContext != null) {
      builderFactoryBean.setApplicationContext(applicationContext);
    }
    builderFactoryBean.setClientId(clientId);
    builderFactoryBean.setSystemProxyProperties(systemProxyProperties);
    builderFactoryBean.setRestProperties(restProperties);
    builderFactoryBean.setAuthorizedClientManager(authorizedClientManager);
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
