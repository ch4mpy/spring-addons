package ${package};

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

import ${package}.exceptions.CustomExceptionHandler;
import com.c4_soft.springaddons.security.oauth2.config.reactive.OidcReactiveApiSecurityConfig;

@SpringBootApplication(scanBasePackageClasses = { SampleApi.class, CustomExceptionHandler.class, OidcReactiveApiSecurityConfig.class })
public class SampleApi {
	public static void main(String[] args) {
		new SpringApplicationBuilder(SampleApi.class).web(WebApplicationType.REACTIVE).run(args);
	}
}
