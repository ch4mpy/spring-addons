package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.ResolvableType;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Same check as Spring Boot's {@code @ConditionalOnMissingBean} for a generic type (which the
 * annotation can only express through the return type of a {@code @Bean} method): matches when no
 * bean definition in the context or its ancestors is assignable to the type, generics included,
 * without eager initialization.
 * <p>
 * Used for the defaults which are injected by a generic type (a {@code Converter<A, B>} for
 * instance): the condition must check the very type the consumers inject, otherwise a bean of that
 * type provided by the application leaves two candidates instead of replacing the default.
 * </p>
 */
public abstract class OnMissingBeanOfGenericTypeCondition implements Condition {
  private final ResolvableType type;

  protected OnMissingBeanOfGenericTypeCondition(ParameterizedTypeReference<?> type) {
    this.type = ResolvableType.forType(type);
  }

  @Override
  public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
    final ListableBeanFactory beanFactory = context.getBeanFactory();
    return beanFactory == null || BeanFactoryUtils
        .beanNamesForTypeIncludingAncestors(beanFactory, type, true, false).length == 0;
  }
}
