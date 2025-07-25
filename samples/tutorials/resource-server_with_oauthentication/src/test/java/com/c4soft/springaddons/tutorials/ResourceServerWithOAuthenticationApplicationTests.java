package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithAnonymousUser;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({AddonsWebmvcTestConf.class})
class ResourceServerWithOAuthenticationApplicationTests {
  @Autowired
  MockMvcSupport api;

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetActuatorHealthLiveness_thenOk() throws Exception {
    api.get("/actuator/health/liveness").andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value("UP"));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetActuatorHealthReadiness_thenOk() throws Exception {
    api.get("/actuator/health/readiness").andExpect(status().isOk());
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetActuator_thenUnauthorized() throws Exception {
    api.get("/actuator").andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockAuthentication("OBSERVABILITY:read")
  void givenUserIsGrantedWithObservabilityRead_whenGetActuator_thenOk() throws Exception {
    api.get("/actuator").andExpect(status().isOk());
  }

  @Test
  @WithMockAuthentication("OBSERVABILITY:write")
  void givenUserIsGrantedWithObservabilityWrite_whenPostActuatorShutdown_thenOk() throws Exception {
    api.post(Map.of("configuredLevel", "debug"), "/actuator/loggers/com.c4soft")
        .andExpect(status().is2xxSuccessful());
  }

  @Test
  @WithMockAuthentication("OBSERVABILITY:read")
  void givenUserIsNotGrantedWithObservabilityWrite_whenPostActuatorShutdown_thenForbidden()
      throws Exception {
    api.post(Map.of("configuredLevel", "debug"), "/actuator/loggers/com.c4soft")
        .andExpect(status().isForbidden());
  }

  @Test
  @WithJwt("auth0_badboy.json")
  void givenUserIsAuthenticated_whenGreet_thenOk() throws Exception {
    api.get("/greet").andExpect(status().isOk()).andExpect(jsonPath("$.body").value(
        "Hi tonton-pirate! You are granted with: [SKIPPER, AUTHOR] and your email is null."));
  }

  @Test
  void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
    api.get("/greet").andExpect(status().isUnauthorized());
  }

  @Test
  @WithJwt("auth0_nice.json")
  void givenUserIsGrantedWithNice_whenGetNice_thenOk() throws Exception {
    api.get("/nice").andExpect(status().isOk()).andExpect(jsonPath("$.body")
        .value("Dear ch4mp! You are granted with: [USER_ROLES_EDITOR, NICE, AUTHOR]."));
  }

  @Test
  @WithJwt("auth0_badboy.json")
  void givenUserIsNotGrantedWithNice_whenGetNice_thenForbidden() throws Exception {
    api.get("/nice").andExpect(status().isForbidden());
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetNice_thenUnauthorized() throws Exception {
    api.get("/nice").andExpect(status().isUnauthorized());
  }
}
