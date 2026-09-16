package com.c4_soft.springaddons.rest.reactive;

import java.util.Optional;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import com.c4_soft.springaddons.rest.AbstractWebClientBuilderFactoryBean;
import lombok.Setter;

@Setter
public class ServerWebClientBuilderFactoryBean extends AbstractWebClientBuilderFactoryBean {
  private Optional<ReactiveOAuth2AuthorizedClientManager> authorizedClientManager;
  private Optional<ServerOAuth2AuthorizedClientRepository> authorizedClientRepository =
      Optional.empty();
  private Optional<ReactiveOAuth2AuthorizedClientService> authorizedClientService =
      Optional.empty();

  @Override
  protected ExchangeFilterFunction registrationExchangeFilterFunction(String Oauth2RegistrationId) {
    return SpringAddonsServerWebClientSupport.registrationExchangeFilterFunction(
        authorizedClientManager.get(), Oauth2RegistrationId,
        SpringAddonsServerAuthorizationFailureHandlerSupport
            .removeAuthorizedClientFailureHandler(authorizedClientRepository,
                authorizedClientService));
  }

  @Override
  protected ExchangeFilterFunction forwardingBearerExchangeFilterFunction() {
    return SpringAddonsServerWebClientSupport.forwardingBearerExchangeFilterFunction();
  }
}
