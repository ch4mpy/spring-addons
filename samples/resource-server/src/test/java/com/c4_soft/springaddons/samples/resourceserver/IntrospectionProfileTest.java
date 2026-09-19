package com.c4_soft.springaddons.samples.resourceserver;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.context.ActiveProfiles;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

/**
 * The same application with the {@code introspection} profile: access tokens are validated by the
 * authorization server instead of a local JWT decoder. {@code @WithOpaqueToken} replaces
 * {@code @WithJwt} (it runs the claim-set through the {@code OpaqueTokenAuthenticationConverter}
 * rather than the JWT one), and nothing else changes: the same claim-set files produce the same
 * {@code OAuthentication<OpenidToken>}, so the endpoints answer exactly as they do with a JWT
 * decoder.
 */
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("introspection")
@ImportAutoConfiguration(AddonsWebmvcTestConf.class)
class IntrospectionProfileTest {

  @Autowired
  MockMvcSupport api;

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetMe_thenUnauthorized() throws Exception {
    api.get("/greetings/me").andExpect(status().isUnauthorized());
  }

  @Test
  @WithOpaqueToken("brice.json")
  void givenUserIsBrice_whenGetMe_thenSameAnswerAsWithAJwtDecoder() throws Exception {
    api.get("/greetings/me").andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value(
            "Hi Brice! You are granted with [NICE, default-roles-spring-addons, offline_access, uma_authorization]."))
        .andExpect(jsonPath("$.username").value("brice"));
  }

  @Test
  @WithOpaqueToken("igor.json")
  void givenUserIsIgor_whenGetNice_thenForbidden() throws Exception {
    api.get("/greetings/nice").andExpect(status().isForbidden());
  }
}
