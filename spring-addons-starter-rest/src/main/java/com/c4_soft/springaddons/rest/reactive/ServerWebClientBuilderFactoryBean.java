package com.c4_soft.springaddons.rest.reactive;

import java.util.Optional;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import com.c4_soft.springaddons.rest.AbstractWebClientBuilderFactoryBean;
import lombok.Setter;

@Setter
public class ServerWebClientBuilderFactoryBean
    extends AbstractWebClientBuilderFactoryBean {
  private Optional<ReactiveClientRegistrationRepository> clientRegistrationRepository;
  private Optional<ServerOAuth2AuthorizedClientRepository> authorizedClientRepository;

  @Override
  protected ExchangeFilterFunction registrationExchangeFilterFunction(
      String Oauth2RegistrationId) {
    return SpringAddonsServerWebClientSupport.registrationExchangeFilterFunction(
        clientRegistrationRepository.get(), authorizedClientRepository.get(),
        Oauth2RegistrationId);
  }

  @Override
  protected ExchangeFilterFunction forwardingBearerExchangeFilterFunction() {
    return SpringAddonsServerWebClientSupport.forwardingBearerExchangeFilterFunction();
  }
}