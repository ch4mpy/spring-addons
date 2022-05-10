package ${package};

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import ${package}.exceptions.CustomExceptionHandler;
import ${package}.domain.SampleEntity;
import ${package}.jpa.SampleEntityRepository;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.OidcServletApiSecurityConfig;

@SpringBootApplication(scanBasePackageClasses = { SampleApi.class, CustomExceptionHandler.class, OidcServletApiSecurityConfig.class })
@EnableJpaRepositories(basePackageClasses = { SampleEntityRepository.class })
@EntityScan(basePackageClasses = { SampleEntity.class })
@EnableTransactionManagement
public class SampleApi {
	public static void main(String[] args) {
		new SpringApplicationBuilder(SampleApi.class).web(WebApplicationType.SERVLET).run(args);
	}
}
