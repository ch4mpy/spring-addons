package com.c4_soft.springaddons.rest.condition;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Matches when {@code com.c4-soft.springaddons.rest.group} is present and non-empty.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class NonEmptySpringAddonsRestGroupCondition extends SpringBootCondition {

  private static final String CONDITION_NAME = "NonEmptySpringAddonsRestGroupCondition";
  private static final String GROUP_PROPERTY = "com.c4-soft.springaddons.rest.group";

  @Override
  public ConditionOutcome getMatchOutcome(ConditionContext context,
      AnnotatedTypeMetadata metadata) {
    final var groups = Binder.get(context.getEnvironment())
        .bind(GROUP_PROPERTY, Bindable.mapOf(String.class, Object.class));

    if (groups.isBound() && !groups.get().isEmpty()) {
      return ConditionOutcome.match(
          ConditionMessage.forCondition(CONDITION_NAME)
              .because("'%s' is non-empty".formatted(GROUP_PROPERTY)));
    }

    return ConditionOutcome.noMatch(
        ConditionMessage.forCondition(CONDITION_NAME)
            .because("'%s' is missing or empty".formatted(GROUP_PROPERTY)));
  }
}
