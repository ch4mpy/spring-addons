package com.c4_soft.springaddons.rest.synchronised;

import java.util.Optional;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.FactoryBean;
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
public class RestClientFactoryBean implements FactoryBean<RestClient> {
  private String clientId;
  private SystemProxyProperties systemProxyProperties;
  private SpringAddonsRestProperties restProperties;
  private Optional<OAuth2AuthorizedClientManager> authorizedClientManager = Optional.empty();
  private Optional<ClientRegistrationRepository> clientRegistrationRepository = Optional.empty();
  private Optional<OAuth2AuthorizedClientRepository> authorizedClientRepository = Optional.empty();
  private Optional<ClientHttpRequestFactory> clientHttpRequestFactory;
  private RestClient.Builder restClientBuilder;

  @Override
  @Nullable
  public RestClient getObject() throws Exception {
    final var builderFactoryBean = new RestClientBuilderFactoryBean();
    builderFactoryBean.setClientId(clientId);
    builderFactoryBean.setSystemProxyProperties(systemProxyProperties);
    builderFactoryBean.setRestProperties(restProperties);
    builderFactoryBean.setAuthorizedClientManager(authorizedClientManager);
    builderFactoryBean.setClientRegistrationRepository(clientRegistrationRepository);
    builderFactoryBean.setAuthorizedClientRepository(authorizedClientRepository);
    builderFactoryBean.setClientHttpRequestFactory(clientHttpRequestFactory);
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
