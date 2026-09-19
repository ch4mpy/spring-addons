package com.c4_soft.springaddons.rest.reactive;

import java.util.Optional;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import com.c4_soft.springaddons.rest.AbstractWebClientBuilderFactoryBean;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import lombok.Setter;

@Setter
public class ServerWebClientBuilderFactoryBean extends AbstractWebClientBuilderFactoryBean {
  private Optional<ReactiveOAuth2AuthorizedClientManager> authorizedClientManager =
      Optional.empty();
  private Optional<ServerOAuth2AuthorizedClientRepository> authorizedClientRepository =
      Optional.empty();
  private Optional<ReactiveOAuth2AuthorizedClientService> authorizedClientService =
      Optional.empty();

  @Override
  protected ExchangeFilterFunction registrationExchangeFilterFunction(String oauth2RegistrationId) {
    if (authorizedClientManager == null || authorizedClientManager.isEmpty()) {
      throw new RestMisconfigurationException(
          "OAuth2 client missconfiguration. Can't setup an OAuth2 Bearer exchange filter function for registration '%s' because there is no ReactiveOAuth2AuthorizedClientManager bean."
              .formatted(oauth2RegistrationId));
    }
    return SpringAddonsServerWebClientSupport.registrationExchangeFilterFunction(
        authorizedClientManager.get(), oauth2RegistrationId,
        SpringAddonsServerAuthorizationFailureHandlerSupport
            .removeAuthorizedClientFailureHandler(authorizedClientRepository,
                authorizedClientService));
  }

  @Override
  protected ExchangeFilterFunction forwardingBearerExchangeFilterFunction() {
    return SpringAddonsServerWebClientSupport.forwardingBearerExchangeFilterFunction();
  }
}
