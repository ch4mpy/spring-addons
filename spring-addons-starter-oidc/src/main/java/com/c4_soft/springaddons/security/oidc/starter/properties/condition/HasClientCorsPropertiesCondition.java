package com.c4_soft.springaddons.security.oidc.starter.properties.condition;

@Deprecated(forRemoval = true)
/**
 * @deprecated default CORS configuration is now made with a filter which is unique in the app (applies to all filter-chains). Use
 *             {@link HasCorsPropertiesCondition}
 */
public class HasClientCorsPropertiesCondition extends HasPropertyPrefixCondition {

    public HasClientCorsPropertiesCondition() {
        super("com.c4-soft.springaddons.oidc.client.cors");
    }
}
