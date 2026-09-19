package com.c4_soft.springaddons.samples.resourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * A REST API secured with JWT access tokens. There is no {@code SecurityFilterChain} bean in this
 * application: spring-addons-starter-oidc builds it from the {@code com.c4-soft.springaddons.oidc}
 * properties in {@code application.yml}.
 */
@SpringBootApplication
public class ResourceServerApplication {

  public static void main(String[] args) {
    SpringApplication.run(ResourceServerApplication.class, args);
  }
}
