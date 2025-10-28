package com.c4soft.springaddons.tutorials;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithAnonymousUser;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oidc.OAuthentication;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
@TestInstance(Lifecycle.PER_CLASS) // Required for @MethodSource with dependency injection (added in @controller test by @AutoConfigureAddonsWebSecurity)
class ResourceServerMultitenantDynamicApplicationTests {
  @Autowired
  MockMvcSupport api;

  @Autowired
  WithJwt.AuthenticationFactory jwtAuthFactory;

  @ParameterizedTest
  @MethodSource("users") // see below for the factory
  void givenUserIsAuthenticated_whenGreet_thenOk(@ParameterizedAuthentication Authentication auth)
      throws Exception {
    final var oauth = (JwtAuthenticationToken) auth;
    final var actual =
        api.get("/greet").andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    assertThat(actual)
        .contains("Hi %s! You are granted with: %s and your email is %s.".formatted(auth.getName(),
            auth.getAuthorities(), oauth.getTokenAttributes().get(StandardClaimNames.EMAIL)));
  }

  @Test
  void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
    api.get("/greet").andExpect(status().isUnauthorized());
  }

  @Test
  @WithJwt("keycloak_nice.json")
  void givenUserIsNice_whenGetNice_thenOk() throws Exception {
    api.get("/nice").andExpect(status().isOk()).andExpect(jsonPath("$.body").value(
        "Dear oauth2|c4-soft|4dd56dbb-71ef-4fe2-9358-3ae3240a9e94! You are granted with: [USER_ROLES_EDITOR, NICE, AUTHOR]."));
  }

  @Test
  @WithJwt("keycloak_badboy.json")
  void givenUserIsNotGrantedWithNice_whenGetNice_thenForbidden() throws Exception {
    api.get("/nice").andExpect(status().isForbidden());
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetNice_thenUnauthorized() throws Exception {
    api.get("/nice").andExpect(status().isUnauthorized());
  }

  /**
   * &#64;MethodSource for &#64;ParameterizedTest
   *
   * @return a stream of {@link OAuthentication OAuthentication&lt;OpenidClaimSet&gt;} as defined by
   *         the Authentication converter in the security configuration
   */
  Stream<AbstractAuthenticationToken> users() {
    return jwtAuthFactory.authenticationsFrom("keycloak_nice.json", "keycloak_badboy.json");
  }

}
