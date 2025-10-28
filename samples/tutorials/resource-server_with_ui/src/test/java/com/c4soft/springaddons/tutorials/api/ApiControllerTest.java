package com.c4soft.springaddons.tutorials.api;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithAnonymousUser;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;
import com.c4soft.springaddons.tutorials.WebSecurityConfig;

@WebMvcTest(controllers = ApiController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
@Import({WebSecurityConfig.class})
class ApiControllerTest {

  @Autowired
  MockMvcSupport mockMvc;

  @Test
  @WithJwt("ch4mp_keycloak.json")
  void givenUserIsAuthenticated_whenApiGreet_thenOk() throws Exception {
    mockMvc.get("/api/greet").andExpect(status().isOk()).andExpect(content().string(
        "Hi 4dd56dbb-71ef-4fe2-9358-3ae3240a9e94! You are authenticated by http://localhost:7080/auth/realms/spring-addons and granted with: [NICE, AUTHOR]."));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenApiGreet_thenUnauthorized() throws Exception {
    mockMvc.get("/api/greet").andExpect(status().isUnauthorized());
  }

}
