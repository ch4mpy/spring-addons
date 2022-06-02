package ${package};

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;

@SpringBootApplication
public class SampleApi {
	public static void main(String[] args) {
		new SpringApplicationBuilder(SampleApi.class).web(WebApplicationType.REACTIVE).run(args);
	}
	
	@EnableReactiveMethodSecurity
	public static class WebSecurityConfig {
	}
}
