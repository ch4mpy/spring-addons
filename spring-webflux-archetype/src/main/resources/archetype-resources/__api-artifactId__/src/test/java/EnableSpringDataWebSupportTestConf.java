package ${package};

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;

import ${package}.domain.SampleEntity;
import ${package}.r2dbc.SampleEntityRepository;

/**
 * Avoid MethodArgumentConversionNotSupportedException with repos MockBean
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
@TestConfiguration
public class EnableSpringDataWebSupportTestConf {
	@Autowired
	SampleEntityRepository sampleRepo;

	@Bean
	WebFluxConfigurer configurer() {
		return new WebFluxConfigurer() {

			@Override
			public void addFormatters(FormatterRegistry registry) {
				registry.addConverter(String.class, SampleEntity.class, id -> sampleRepo.findById(Long.valueOf(id)).block());
			}
		};
	}
}