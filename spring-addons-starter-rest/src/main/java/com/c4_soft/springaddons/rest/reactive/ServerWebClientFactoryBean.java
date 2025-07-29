package com.c4_soft.springaddons.rest.reactive;

import java.util.Optional;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.boot.autoconfigure.web.reactive.function.client.WebClientSsl;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;
import lombok.Setter;
import lombok.experimental.FieldNameConstants;

@Setter
@FieldNameConstants
public class ServerWebClientFactoryBean implements FactoryBean<WebClient> {
  private String clientId;
  private SystemProxyProperties systemProxyProperties;
  private SpringAddonsRestProperties restProperties;
  private Optional<ReactiveOAuth2AuthorizedClientManager> authorizedClientManager =
      Optional.empty();
  private WebClient.Builder webClientBuilder;
  private Optional<WebClientSsl> ssl = Optional.empty();

  @Override
  @Nullable
  public WebClient getObject() throws Exception {
    final var builderFactoryBean = new ServerWebClientBuilderFactoryBean();
    builderFactoryBean.setClientId(clientId);
    builderFactoryBean.setSystemProxyProperties(systemProxyProperties);
    builderFactoryBean.setRestProperties(restProperties);
    builderFactoryBean.setAuthorizedClientManager(authorizedClientManager);
    builderFactoryBean.setWebClientBuilder(webClientBuilder);
    builderFactoryBean.setSsl(ssl);
    return Optional.ofNullable(builderFactoryBean.getObject()).map(WebClient.Builder::build)
        .orElse(null);
  }

  @Override
  @Nullable
  public Class<?> getObjectType() {
    return WebClient.class;
  }
}
