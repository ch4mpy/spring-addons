package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OidcBackChannelLogoutHandler;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@AutoConfigureAddonsWebmvcResourceServerSecurity
@ImportAutoConfiguration({AddonsWebmvcTestConf.class, OAuth2ClientProperties.class})
class ResourceServerWithUiApplicationTests {
  @Autowired
  MockMvcSupport api;

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenApiGreet_thenUnauthorized() throws Exception {
    api.get("/api/greet").andExpect(status().isUnauthorized());
  }

  @Test
  @WithJwt("ch4mp_keycloak.json")
  void givenUserIsAuthenticated_whenApiGreet_thenOk() throws Exception {
    api.get("/api/greet").andExpect(status().isOk()).andExpect(content().string(
        "Hi 4dd56dbb-71ef-4fe2-9358-3ae3240a9e94! You are authenticated by http://localhost:7080/auth/realms/spring-addons and granted with: [NICE, AUTHOR]."));
  }

  @TestConfiguration
  static class TestConf {

    @Bean
    LogoutHandler truc(OidcSessionRegistry sessionRegistry) {
      return new OidcBackChannelLogoutHandler(sessionRegistry);
    }
  }
}
