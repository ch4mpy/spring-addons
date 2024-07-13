package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.context.annotation.Conditional;

import com.c4_soft.springaddons.security.oidc.starter.properties.condition.HasClientCorsPropertiesCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.HasCorsPropertiesCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.HasResourceServerCorsPropertiesCondition;

@Deprecated(forRemoval = true)
/**
 * @deprecated default CORS configuration is now made with a filter which is unique in the app (applies to all filter-chains). Use
 *             {@link HasCorsPropertiesCondition}
 */
public class BackwardCompatibleCorsPropertiesCondition extends AnyNestedCondition {

    public BackwardCompatibleCorsPropertiesCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @Conditional(HasCorsPropertiesCondition.class)
    static class HasNewPropertiesCondition {}

    @Conditional(HasClientCorsPropertiesCondition.class)
    static class HasClientPropertiesCondition {}

    @Conditional(HasResourceServerCorsPropertiesCondition.class)
    static class HasResourceServerPropertiesCondition {}

}
