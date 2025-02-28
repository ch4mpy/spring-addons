package com.c4_soft.springaddons.rest.synchronised;

import java.util.Optional;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import com.c4_soft.springaddons.rest.AbstractWebClientBuilderFactoryBean;
import lombok.Setter;

@Setter
public class ServletWebClientBuilderFactoryBean extends AbstractWebClientBuilderFactoryBean {
  private Optional<OAuth2AuthorizedClientManager> authorizedClientManager;

  @Override
  protected ExchangeFilterFunction registrationExchangeFilterFunction(String Oauth2RegistrationId) {
    return SpringAddonsServletWebClientSupport
        .registrationExchangeFilterFunction(authorizedClientManager.get(), Oauth2RegistrationId);
  }

  @Override
  protected ExchangeFilterFunction forwardingBearerExchangeFilterFunction() {
    return SpringAddonsServletWebClientSupport.forwardingBearerExchangeFilterFunction();
  }
}
