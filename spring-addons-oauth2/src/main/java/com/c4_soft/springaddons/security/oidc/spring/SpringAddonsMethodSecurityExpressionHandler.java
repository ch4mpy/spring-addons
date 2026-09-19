package com.c4_soft.springaddons.security.oidc.spring;

import java.lang.reflect.Method;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.expression.MethodBasedEvaluationContext;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

/**
 * A {@link DefaultMethodSecurityExpressionHandler} using a custom
 * {@link SpringAddonsMethodSecurityExpressionRoot}.
 *
 * <pre>
 * &#64;Bean
 * static MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
 *   return new SpringAddonsMethodSecurityExpressionHandler(MyExpressionRoot::new);
 * }
 *
 * static final class MyExpressionRoot extends SpringAddonsMethodSecurityExpressionRoot {
 *   MyExpressionRoot(Supplier&lt;? extends Authentication&gt; authentication,
 *       MethodInvocation invocation) {
 *     super(authentication, invocation);
 *   }
 *   ...
 * }
 * </pre>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsMethodSecurityExpressionHandler
    extends DefaultMethodSecurityExpressionHandler {
  private final BiFunction<Supplier<? extends @Nullable Authentication>, MethodInvocation, ? extends SpringAddonsMethodSecurityExpressionRoot> expressionRootFactory;

  /**
   * @param expressionRootFactory builds the expression root from the {@link Authentication}
   *        supplier Spring Security hands to this handler and the secured method invocation, so
   *        that the root does not depend on the {@code SecurityContextHolder} (see
   *        {@link SpringAddonsMethodSecurityExpressionRoot#SpringAddonsMethodSecurityExpressionRoot(Supplier, MethodInvocation)})
   */
  public SpringAddonsMethodSecurityExpressionHandler(
      BiFunction<Supplier<? extends @Nullable Authentication>, MethodInvocation, ? extends SpringAddonsMethodSecurityExpressionRoot> expressionRootFactory) {
    this.expressionRootFactory = expressionRootFactory;
  }

  /**
   * @param expressionRootSupplier builds an expression root which retrieves the
   *        {@link Authentication} on its own (from the {@code SecurityContextHolder})
   * @deprecated use {@link #SpringAddonsMethodSecurityExpressionHandler(BiFunction)} with a root
   *             built from the {@link Authentication} supplier and the method invocation
   */
  @Deprecated
  public SpringAddonsMethodSecurityExpressionHandler(
      Supplier<? extends SpringAddonsMethodSecurityExpressionRoot> expressionRootSupplier) {
    this((authentication, invocation) -> expressionRootSupplier.get());
  }

  /**
   * Creates the root object for expression evaluation.
   */
  @Override
  protected MethodSecurityExpressionOperations createSecurityExpressionRoot(
      Authentication authentication, MethodInvocation invocation) {
    return createSecurityExpressionRoot(() -> authentication, invocation);
  }

  @Override
  public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication,
      MethodInvocation mi) {
    var root = createSecurityExpressionRoot(authentication, mi);
    var ctx =
        new SpringAddonsMethodSecurityEvaluationContext(root, mi, getParameterNameDiscoverer());
    ctx.setBeanResolver(getBeanResolver());
    return ctx;
  }

  private MethodSecurityExpressionOperations createSecurityExpressionRoot(
      Supplier<? extends @Nullable Authentication> authentication, MethodInvocation invocation) {
    final var root = expressionRootFactory.apply(authentication, invocation);
    root.setThis(invocation.getThis());
    root.setPermissionEvaluator(getPermissionEvaluator());
    root.setTrustResolver(getTrustResolver());
    root.setRoleHierarchy(getRoleHierarchy());
    root.setDefaultRolePrefix(getDefaultRolePrefix());
    return root;
  }

  static class SpringAddonsMethodSecurityEvaluationContext extends MethodBasedEvaluationContext {

    SpringAddonsMethodSecurityEvaluationContext(MethodSecurityExpressionOperations root,
        MethodInvocation mi, ParameterNameDiscoverer parameterNameDiscoverer) {
      super(root, getSpecificMethod(mi), mi.getArguments(), parameterNameDiscoverer);
    }

    private static Method getSpecificMethod(MethodInvocation mi) {
      return AopUtils.getMostSpecificMethod(mi.getMethod(),
          AopProxyUtils.ultimateTargetClass(mi.getThis()));
    }

  }

}
