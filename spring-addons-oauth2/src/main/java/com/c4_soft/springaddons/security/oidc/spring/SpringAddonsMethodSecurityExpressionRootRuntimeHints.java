package com.c4_soft.springaddons.security.oidc.spring;

import org.jspecify.annotations.Nullable;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;

/**
 * Registers, for native images, the public methods of {@link SpringAddonsMethodSecurityExpressionRoot},
 * which SpEL calls by reflection: {@code this}, {@code returnObject} or {@code filterObject} in a
 * method security expression. The methods an application adds in its own expression root need
 * hints of their own (see {@link SpringAddonsMethodSecurityExpressionHandler}).
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsMethodSecurityExpressionRootRuntimeHints implements RuntimeHintsRegistrar {

  @Override
  public void registerHints(RuntimeHints hints, @Nullable ClassLoader classLoader) {
    hints.reflection().registerType(SpringAddonsMethodSecurityExpressionRoot.class,
        MemberCategory.INVOKE_PUBLIC_METHODS);
  }
}
