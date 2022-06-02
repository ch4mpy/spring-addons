package ${package};

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import ${package}.domain.SampleEntity;
import ${package}.exceptions.CustomExceptionHandler;
import ${package}.jpa.SampleEntityRepository;

@SpringBootApplication(scanBasePackageClasses = { SampleApi.class, CustomExceptionHandler.class })
public class SampleApi {
	public static void main(String[] args) {
		new SpringApplicationBuilder(SampleApi.class).web(WebApplicationType.SERVLET).run(args);
	}

	@EnableGlobalMethodSecurity(prePostEnabled = true)
	public static class WebSecurityConfig {
	}

	@EnableJpaRepositories(basePackageClasses = { SampleEntityRepository.class })
	@EntityScan(basePackageClasses = { SampleEntity.class })
	@EnableTransactionManagement
	public static class PersistenceConfig {
	}
}
