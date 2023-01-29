package com.c4_soft.springaddons.security.oauth2.config;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Arrays;

import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.annotation.AliasFor;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.METHOD })
@Conditional(ConditionalOnMissingProperty.MissingPropertyCondition.class)
public @interface ConditionalOnMissingProperty {

    String PROPERTY_KEYS = "propertyKeys";

    @AliasFor(PROPERTY_KEYS)
    String[] value() default {};

    @AliasFor("value")
    String[] propertyKeys() default {};

    class MissingPropertyCondition extends SpringBootCondition {
        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            String[] keys = (String[]) metadata.getAnnotationAttributes(ConditionalOnMissingProperty.class.getName()).get(PROPERTY_KEYS);
            if (keys.length > 0) {
                boolean allMissing = true;
                for (String key : keys) {
                    String propertyValue = context.getEnvironment().getProperty(key);
                    String propertyValueList = context.getEnvironment().getProperty(key + "[0]"); //in case of list
                    allMissing &= (!StringUtils.hasText(propertyValue) && !StringUtils.hasText(propertyValueList));
                }
                if (allMissing) {
                    return new ConditionOutcome(true, "The following properties were all null or empty in the environment: " + Arrays.toString(keys));
                }
                return new ConditionOutcome(false, "one or more properties were found.");
            } else {
                throw new RuntimeException("expected method annotated with " + ConditionalOnMissingProperty.class.getName() + " to include a non-empty " + PROPERTY_KEYS + " attribute");
            }
        }
    }
}