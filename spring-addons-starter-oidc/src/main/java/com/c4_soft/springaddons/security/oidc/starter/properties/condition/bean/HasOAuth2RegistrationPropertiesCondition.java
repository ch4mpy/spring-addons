package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class HasOAuth2RegistrationPropertiesCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        final String prefix = "spring.security.oauth2.client.registration";
        if (context.getEnvironment() instanceof ConfigurableEnvironment env) {
            for (PropertySource<?> propertySource : env.getPropertySources()) {
                if (propertySource instanceof EnumerablePropertySource enumerablePropertySource) {
                    for (String key : enumerablePropertySource.getPropertyNames()) {
                        if (key.startsWith(prefix)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}