package com.c4_soft.springaddons.samples.resourceserver.greetings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import com.c4_soft.springaddons.samples.resourceserver.SecurityConfig;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oidc.OAuthentication;

/**
 * The scenario of <a href="https://github.com/ch4mpy/spring-addons/issues/181">issue #181</a>: two
 * JWT authentication converter beans in the context, the one from {@link SecurityConfig} and a
 * plain {@link JwtAuthenticationConverter} under a name of its own. The auto-configured filter
 * chain takes the {@code @Primary} one (or the one named {@code jwtAuthenticationConverter}), and
 * so do the test annotations, unless {@code authenticationConverterBeanName} says otherwise.
 */
@WebMvcTest(GreetingsController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
@Import({SecurityConfig.class, GreetingsService.class,
    SeveralAuthenticationConvertersTest.SecondConverterConfig.class})
class SeveralAuthenticationConvertersTest {

  @Autowired
  MockMvcSupport api;

  @Test
  @WithJwt("brice.json")
  void givenNoConverterIsNamed_thenPrimaryOneBuildsTheAuthentication() {
    assertThat(SecurityContextHolder.getContext().getAuthentication())
        .isInstanceOf(JwtAuthenticationToken.class);
  }

  @Test
  @WithJwt(value = "brice.json", authenticationConverterBeanName = "authenticationConverter")
  void givenApplicationConverterIsNamed_whenGetMe_thenGreetedAsAtRuntime() throws Exception {
    assertThat(SecurityContextHolder.getContext().getAuthentication())
        .isInstanceOf(OAuthentication.class);
    api.get("/greetings/me").andExpect(status().isOk());
  }

  @TestConfiguration
  static class SecondConverterConfig {
    @Bean
    @Primary
    JwtAuthenticationConverter defaultJwtAuthenticationConverter() {
      return new JwtAuthenticationConverter();
    }
  }
}
