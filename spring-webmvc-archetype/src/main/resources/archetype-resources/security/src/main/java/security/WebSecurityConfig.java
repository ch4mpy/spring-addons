package ${package}.security;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import com.c4_soft.springaddons.security.oauth2.config.OidcServletApiSecurityConfig;
import com.c4_soft.springaddons.security.oauth2.config.ServletSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Import({ SpringAddonsSecurityProperties.class, ServletSecurityBeans.class })
public class WebSecurityConfig extends OidcServletApiSecurityConfig {
	public WebSecurityConfig(
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver,
			SpringAddonsSecurityProperties securityProperties,
			ServerProperties serverProperties) {
		super(authenticationManagerResolver, securityProperties, serverProperties);
	}
}
