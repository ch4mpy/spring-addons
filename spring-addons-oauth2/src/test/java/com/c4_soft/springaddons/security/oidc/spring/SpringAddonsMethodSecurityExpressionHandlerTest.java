package com.c4_soft.springaddons.security.oidc.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.lang.reflect.Method;
import java.util.function.Supplier;
import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

class SpringAddonsMethodSecurityExpressionHandlerTest {

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void givenAuthenticationSupplier_whenCreateEvaluationContext_thenRootUsesItAndNotTheSecurityContextHolder()
      throws Exception {
    // The SecurityContextHolder holds another authentication than the one Spring Security supplies
    SecurityContextHolder.setContext(
        new SecurityContextImpl(new TestingAuthenticationToken("holder", "", "ROLE_HOLDER")));
    final var supplied = new TestingAuthenticationToken("supplied", "", "ROLE_SUPPLIED");
    final var handler = new SpringAddonsMethodSecurityExpressionHandler(Root::new);

    final var ctx = handler.createEvaluationContext(() -> supplied, invocation());
    final var root = (MethodSecurityExpressionOperations) ctx.getRootObject().getValue();

    assertThat(root).isInstanceOf(Root.class);
    assertThat(root.getAuthentication()).isSameAs(supplied);
    assertThat(root.getThis()).isInstanceOf(Target.class);
    assertThat(new SpelExpressionParser().parseExpression("hasRole('SUPPLIED') && isSupplied()")
        .getValue(ctx, Boolean.class)).isTrue();
    assertThat(new SpelExpressionParser().parseExpression("hasRole('HOLDER')").getValue(ctx,
        Boolean.class)).isFalse();
  }

  private static MethodInvocation invocation() throws NoSuchMethodException {
    final var target = new Target();
    final Method method = Target.class.getMethod("secured", String.class);
    final var invocation = mock(MethodInvocation.class);
    when(invocation.getThis()).thenReturn(target);
    when(invocation.getMethod()).thenReturn(method);
    when(invocation.getArguments()).thenReturn(new Object[] {"arg"});
    return invocation;
  }

  public static class Target {
    public String secured(String param) {
      return param;
    }
  }

  static class Root extends SpringAddonsMethodSecurityExpressionRoot {
    Root(Supplier<? extends @Nullable Authentication> authentication,
        @Nullable MethodInvocation invocation) {
      super(authentication, invocation);
    }

    public boolean isSupplied() {
      return "supplied".equals(getAuthentication().getName());
    }
  }
}
