package com.c4_soft.springaddons.security.oidc.spring;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;

class SpringAddonsMethodSecurityExpressionRootTest {

  @Test
  void givenAuthenticationIsOfExpectedType_whenGet_thenPresent() {
    final var auth = new OAuthentication<>(
        new OpenidToken(Map.of("sub", "ch4mp"), "sub", "a.b.c"), List.of());

    assertThat(new Root(auth).get(OAuthentication.class)).contains(auth);
    // a super-type is accepted too
    assertThat(new Root(auth).get(Authentication.class)).contains(auth);
  }

  @Test
  void givenAuthenticationIsOfASubTypeOfExpectedType_whenGet_thenPresent() {
    final var auth = new SpecializedAuthentication();

    assertThat(new Root(auth).get(TestingAuthenticationToken.class)).contains(auth);
  }

  @Test
  void givenAuthenticationIsOfAnotherType_whenGet_thenEmpty() {
    final var auth = new TestingAuthenticationToken("ch4mp", "secret");

    assertThat(new Root(auth).get(OAuthentication.class)).isEmpty();
    // expecting a sub-type of the actual authentication is not a match either
    assertThat(new Root(auth).get(SpecializedAuthentication.class)).isEmpty();
  }

  static class Root extends SpringAddonsMethodSecurityExpressionRoot {
    Root(Authentication authentication) {
      this(() -> authentication, null);
    }

    Root(Supplier<? extends @Nullable Authentication> authentication,
        @Nullable MethodInvocation invocation) {
      super(authentication, invocation);
    }

    @Override
    public <T extends Authentication> Optional<T> get(Class<T> expectedAuthType) {
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
