package com.c4_soft.springaddons.rest;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * <p>
 * Matches as soon as at least one property key starts with the given prefix.
 * </p>
 * <p>
 * This is how a {@code Map}-typed {@code @ConfigurationProperties} property is detected as
 * non-empty: it has no single value of its own, only entry-scoped sub-properties (for instance,
 * "com.c4-soft.springaddons.rest.group" is populated through keys such as
 * "com.c4-soft.springaddons.rest.group.some-group.client").
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class HasPropertyPrefixCondition implements Condition {

  private final String prefix;

  protected HasPropertyPrefixCondition(String prefix) {
    this.prefix = prefix;
  }

  @Override
  public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
    if (context.getEnvironment() instanceof ConfigurableEnvironment env) {
      for (PropertySource<?> propertySource : env.getPropertySources()) {
        if (propertySource instanceof EnumerablePropertySource<?> enumerablePropertySource) {
          for (String key : enumerablePropertySource.getPropertyNames()) {
            if (key.startsWith(prefix + ".") || key.startsWith(prefix + "[")) {
              return true;
            }
          }
        }
      }
    }
    return false;
  }
}
