package ${package};

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import ${package}.domain.SampleEntity;
import ${package}.jpa.SampleEntityRepository;

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
	WebMvcConfigurer configurer() {
		return new WebMvcConfigurer() {

			@Override
			public void addFormatters(FormatterRegistry registry) {
				registry.addConverter(String.class, SampleEntity.class, id -> sampleRepo.findById(Long.valueOf(id)).get());
			}
		};
	}
}