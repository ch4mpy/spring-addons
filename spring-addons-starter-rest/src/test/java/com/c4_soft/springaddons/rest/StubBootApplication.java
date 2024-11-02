package com.c4_soft.springaddons.rest;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication class StubBootApplication {

  @Bean
  SpringAddonsClientHttpRequestFactory springAddonsClientHttpRequestFactory(
      SystemProxyProperties systemProperties, SpringAddonsRestProperties addonsProperties) {
    return new SpringAddonsClientHttpRequestFactory(systemProperties,
        addonsProperties.getClient().get("test").getHttp());
  }
}