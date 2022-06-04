package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2AuthenticationConverter;
import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.JwtGrantedAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

import lombok.Data;
import lombok.EqualsAndHashCode;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

	public interface ProxiesConverter extends Converter<Jwt, Map<String, List<String>>> {
	}

	@SuppressWarnings("unchecked")
	@Bean
	public ProxiesConverter proxiesConverter() {
		return jwt -> {
			final var proxiesClaim = jwt.getClaims().get("proxies");
			if (proxiesClaim == null) {
				return Map.of();
			}
			return (Map<String, List<String>>) proxiesClaim;
		};
	}

	@Bean
	public SynchronizedJwt2AuthenticationConverter<MyAuthentication> authenticationConverter(
			SynchronizedJwt2OidcTokenConverter<OidcToken> tokenConverter,
			JwtGrantedAuthoritiesConverter authoritiesConverter,
			ProxiesConverter proxiesConverter) {
		return jwt -> new MyAuthentication(tokenConverter.convert(jwt), authoritiesConverter.convert(jwt), proxiesConverter.convert(jwt), jwt.getTokenValue());
	}

	@Data
	@EqualsAndHashCode(callSuper = true)
	public static class MyAuthentication extends OidcAuthentication<OidcToken> {
		private static final long serialVersionUID = 6856299734098317908L;

		private final Map<String, List<String>> proxies;

		public MyAuthentication(OidcToken token, Collection<? extends GrantedAuthority> authorities, Map<String, List<String>> proxies, String bearerString) {
			super(token, authorities, bearerString);
			final Map<String, List<String>> tmp = new HashMap<>(proxies.size());
			proxies.forEach((k, v) -> tmp.put(k, Collections.unmodifiableList(v)));
			this.proxies = Collections.unmodifiableMap(tmp);
		}
	}

	@Component
	public static class MyMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

		@Override
		protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, MethodInvocation invocation) {
			final var root = new MyMethodSecurityExpressionRoot(authentication);
			root.setThis(invocation.getThis());
			root.setPermissionEvaluator(getPermissionEvaluator());
			root.setTrustResolver(getTrustResolver());
			root.setRoleHierarchy(getRoleHierarchy());
			root.setDefaultRolePrefix(getDefaultRolePrefix());
			return root;
		}

		static final class MyMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

			private Object filterObject;
			private Object returnObject;
			private Object target;

			public MyMethodSecurityExpressionRoot(Authentication authentication) {
				super(authentication);
			}

			public boolean hasProxy(String subject, String permission) {
				final var auth = (MyAuthentication) this.getAuthentication();
				return subject == null || permission == null ? false : auth.getProxies().getOrDefault(subject, List.of()).contains(permission);
			}

			@Override
			public void setFilterObject(Object filterObject) {
				this.filterObject = filterObject;
			}

			@Override
			public Object getFilterObject() {
				return filterObject;
			}

			@Override
			public void setReturnObject(Object returnObject) {
				this.returnObject = returnObject;
			}

			@Override
			public Object getReturnObject() {
				return returnObject;
			}

			void setThis(Object target) {
				this.target = target;
			}

			@Override
			public Object getThis() {
				return target;
			}

		}
	}
}