package com.c4soft.springaddons.tutorials.ui;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.rest.RestClientHttpExchangeProxyFactoryBean;

@Configuration
public class RestClientsConfig {

  @Bean
  GreetApi greetApi(RestClient greetClient) throws Exception {
    return new RestClientHttpExchangeProxyFactoryBean<>(GreetApi.class, greetClient).getObject();
  }

}
