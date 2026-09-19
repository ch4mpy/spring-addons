package com.c4_soft.springaddons.samples.restclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * A resource server which is itself a client of two other APIs. Both REST clients, with their base
 * URL, timeouts, headers and OAuth2 authorization, are auto-configured by spring-addons-starter-rest
 * from {@code com.c4-soft.springaddons.rest} properties: there is no {@code RestClient} bean
 * definition in this application.
 */
@SpringBootApplication
@EnableMethodSecurity
public class RestClientApplication {

  public static void main(String[] args) {
    SpringApplication.run(RestClientApplication.class, args);
  }
}
