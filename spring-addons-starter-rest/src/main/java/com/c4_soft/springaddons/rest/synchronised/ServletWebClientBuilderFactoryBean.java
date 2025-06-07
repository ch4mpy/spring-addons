package com.c4_soft.springaddons.rest.synchronised;

import java.util.Optional;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import com.c4_soft.springaddons.rest.AbstractWebClientBuilderFactoryBean;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import lombok.Setter;
import lombok.experimental.FieldNameConstants;

@Setter
@FieldNameConstants
public class ServletWebClientBuilderFactoryBean extends AbstractWebClientBuilderFactoryBean {
  private Optional<OAuth2AuthorizedClientManager> authorizedClientManager;
  private Optional<ClientRegistrationRepository> clientRegistrationRepository;

  @Override
  protected ExchangeFilterFunction registrationExchangeFilterFunction(String registrationId) {
    if (authorizedClientManager.isEmpty()) {
      throw new RestMisconfigurationException(
          "OAuth2 client missconfiguration. Can't setup an OAuth2 Bearer request interceptor because there is no OAuth2AuthorizedClientManager bean.");
    }
    if (clientRegistrationRepository.isEmpty()) {
      throw new RestMisconfigurationException(
          "OAuth2 client missconfiguration. Can't setup an OAuth2 Bearer request interceptor because there is no ClientRegistrationRepository bean.");
    }

    final var registration =
        clientRegistrationRepository.get().findByRegistrationId(registrationId);
    if (registration == null) {
      throw new RestMisconfigurationException(
          "OAuth2 client missconfiguration. %s is not a known OAuth2 client registration."
              .formatted(registrationId));
    }
    return SpringAddonsServletWebClientSupport
        .registrationExchangeFilterFunction(authorizedClientManager.get(), registration);
  }

  @Override
  protected ExchangeFilterFunction forwardingBearerExchangeFilterFunction() {
    return SpringAddonsServletWebClientSupport.forwardingBearerExchangeFilterFunction();
  }
}
