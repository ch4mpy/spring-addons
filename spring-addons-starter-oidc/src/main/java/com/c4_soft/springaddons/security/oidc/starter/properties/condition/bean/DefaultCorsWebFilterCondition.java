package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Conditional;
import org.springframework.web.cors.reactive.CorsWebFilter;

public class DefaultCorsWebFilterCondition extends AllNestedConditions {

    public DefaultCorsWebFilterCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @Conditional(BackwardCompatibleCorsPropertiesCondition.class)
    static class HasCorsPropertiesCondition {}

    @ConditionalOnMissingBean(CorsWebFilter.class)
    static class NoCorsFilterRegisteredCondition {}

}
