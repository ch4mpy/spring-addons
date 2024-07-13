package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Conditional;
import org.springframework.web.filter.CorsFilter;

public class DefaultCorsFilterCondition extends AllNestedConditions {

    public DefaultCorsFilterCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @Conditional(BackwardCompatibleCorsPropertiesCondition.class)
    static class HasCorsPropertiesCondition {}

    @ConditionalOnMissingBean(CorsFilter.class)
    static class NoCorsFilterRegisteredCondition {}

}
