package com.c4_soft.springaddons.rest.synchronised;

import java.util.Optional;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import com.c4_soft.springaddons.rest.AbstractWebClientBuilderFactoryBean;
import lombok.Setter;

@Setter
public class ServletWebClientBuilderFactoryBean
    extends AbstractWebClientBuilderFactoryBean {
  private Optional<ClientRegistrationRepository> clientRegistrationRepository;
  private Optional<OAuth2AuthorizedClientRepository> authorizedClientRepository;

  @Override
  protected ExchangeFilterFunction registrationExchangeFilterFunction(
      String Oauth2RegistrationId) {
    return SpringAddonsServletWebClientSupport.registrationExchangeFilterFunction(
        clientRegistrationRepository.get(), authorizedClientRepository.get(),
        Oauth2RegistrationId);
  }

  @Override
  protected ExchangeFilterFunction forwardingBearerExchangeFilterFunction() {
    return SpringAddonsServletWebClientSupport.forwardingBearerExchangeFilterFunction();
  }
}