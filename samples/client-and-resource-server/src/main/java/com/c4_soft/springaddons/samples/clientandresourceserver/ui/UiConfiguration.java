package com.c4_soft.springaddons.samples.clientandresourceserver.ui;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.rest.RestClientHttpExchangeProxyFactoryBean;

@Configuration
public class UiConfiguration {

  /**
   * @param greetingsApiClient the {@code RestClient} auto-configured by spring-addons-starter-rest
   *        from {@code com.c4-soft.springaddons.rest.client.greetings-api-client}: its requests are
   *        authorized with the access token the client filter chain keeps in session for the
   *        {@code spring-addons-user} registration.
   */
  @Bean
  GreetingsApi greetingsApi(RestClient greetingsApiClient) throws Exception {
    return new RestClientHttpExchangeProxyFactoryBean<>(GreetingsApi.class, greetingsApiClient)
        .getObject();
  }
}
