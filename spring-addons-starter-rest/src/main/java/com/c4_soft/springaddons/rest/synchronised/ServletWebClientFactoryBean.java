package com.c4_soft.springaddons.rest.synchronised;

import java.util.Optional;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;
import lombok.Setter;

@Setter
public class ServletWebClientFactoryBean implements FactoryBean<WebClient> {
  private String clientId;
  private SystemProxyProperties systemProxyProperties;
  private SpringAddonsRestProperties restProperties;
  private Optional<ClientRegistrationRepository> clientRegistrationRepository = Optional.empty();
  private Optional<OAuth2AuthorizedClientRepository> authorizedClientRepository =
      Optional.empty();

  @Override
  @Nullable
  public WebClient getObject() throws Exception {
    final var builderFactoryBean = new ServletWebClientBuilderFactoryBean();
    builderFactoryBean.setClientId(clientId);
    builderFactoryBean.setSystemProxyProperties(systemProxyProperties);
    builderFactoryBean.setRestProperties(restProperties);
    builderFactoryBean.setClientRegistrationRepository(clientRegistrationRepository);
    builderFactoryBean.setAuthorizedClientRepository(authorizedClientRepository);
    return Optional.ofNullable(builderFactoryBean.getObject()).map(WebClient.Builder::build)
        .orElse(null);
  }

  @Override
  @Nullable
  public Class<?> getObjectType() {
    return WebClient.class;
  }
}