package com.c4_soft.springaddons.security.oidc.spring;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;

class SpringAddonsMethodSecurityExpressionRootTest {

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void givenAuthenticationIsOfExpectedType_whenGet_thenPresent() {
    final var auth = new OAuthentication<>(
        new OpenidToken(Map.of("sub", "ch4mp"), "sub", "a.b.c"), List.of());
    SecurityContextHolder.setContext(new SecurityContextImpl(auth));

    assertThat(new Root().get(OAuthentication.class)).contains(auth);
    // a super-type is accepted too
    assertThat(new Root().get(Authentication.class)).contains(auth);
  }

  @Test
  void givenAuthenticationIsOfASubTypeOfExpectedType_whenGet_thenPresent() {
    final var auth = new SpecializedAuthentication();
    SecurityContextHolder.setContext(new SecurityContextImpl(auth));

    assertThat(new Root().get(TestingAuthenticationToken.class)).contains(auth);
  }

  @Test
  void givenAuthenticationIsOfAnotherType_whenGet_thenEmpty() {
    SecurityContextHolder.setContext(
        new SecurityContextImpl(new TestingAuthenticationToken("ch4mp", "secret")));

    assertThat(new Root().get(OAuthentication.class)).isEmpty();
    // expecting a sub-type of the actual authentication is not a match either
    assertThat(new Root().get(SpecializedAuthentication.class)).isEmpty();
  }

  static class Root extends SpringAddonsMethodSecurityExpressionRoot {
    @Override
    public <T extends Authentication> java.util.Optional<T> get(Class<T> expectedAuthType) {
      return super.get(expectedAuthType);
    }
  }

  static class SpecializedAuthentication extends TestingAuthenticationToken {
    private static final long serialVersionUID = 1L;

    SpecializedAuthentication() {
      super("ch4mp", "secret");
    }
  }
}
