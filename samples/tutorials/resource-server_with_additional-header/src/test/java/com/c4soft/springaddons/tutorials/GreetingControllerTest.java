package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithAnonymousUser;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
@Import(SecurityConfig.class)
class GreetingControllerTest {

  @Autowired
  MockMvcSupport api;

  @Test
  @WithMyAuth(authorities = {"AUTHOR"}, idClaims = @OpenIdClaims(email = "ch4mp@c4-soft.com"))
  void givenUserIsAuthenticated_whenGreet_thenOk() throws Exception {
    api.get("/greet").andExpect(status().isOk()).andExpect(
        jsonPath("$.body").value("Hi ch4mp@c4-soft.com! You are granted with: [AUTHOR]."));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
    api.get("/greet").andExpect(status().isUnauthorized());
  }

}
