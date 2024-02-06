package com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsClientWithLoginCondition;

public class DefaultGrantedAuthoritiesMapperCondition extends AllNestedConditions {
	DefaultGrantedAuthoritiesMapperCondition() {
		super(ConfigurationPhase.REGISTER_BEAN);
	}

	@Conditional(IsClientWithLoginCondition.class)
	static class SpringAddonsOidcClientEnabled {
	}

	@ConditionalOnMissingBean(GrantedAuthoritiesMapper.class)
	static class CustomGrantedAuthoritiesMapperNotProvided {
	}
}