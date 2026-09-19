package com.c4_soft.springaddons.samples.resourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;

/**
 * The reactive twin of the {@code resource-server} sample: same properties, same test annotations,
 * a {@code SecurityWebFilterChain} instead of a {@code SecurityFilterChain}. This one keeps Spring's
 * default {@code JwtAuthenticationToken} (no authentication converter bean).
 */
@SpringBootApplication
@EnableReactiveMethodSecurity
public class ResourceServerReactiveApplication {

  public static void main(String[] args) {
    SpringApplication.run(ResourceServerReactiveApplication.class, args);
  }
}
