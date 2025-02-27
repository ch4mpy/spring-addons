package com.c4_soft.springaddons.rest.reactive;

import java.util.Optional;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import com.c4_soft.springaddons.rest.AbstractWebClientBuilderFactoryBean;
import lombok.Setter;

@Setter
public class ServerWebClientBuilderFactoryBean extends AbstractWebClientBuilderFactoryBean {
  private Optional<ReactiveOAuth2AuthorizedClientManager> authorizedClientManager;

  @Override
  protected ExchangeFilterFunction registrationExchangeFilterFunction(String Oauth2RegistrationId) {
    return SpringAddonsServerWebClientSupport
        .registrationExchangeFilterFunction(authorizedClientManager.get(), Oauth2RegistrationId);
  }

  @Override
  protected ExchangeFilterFunction forwardingBearerExchangeFilterFunction() {
    return SpringAddonsServerWebClientSupport.forwardingBearerExchangeFilterFunction();
  }
}
