package ${package}.r2dbc;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.r2dbc.config.AbstractR2dbcConfiguration;

import ${package}.r2dbc.SampleEntityRepository.SampleEntityReadingConverter;
import ${package}.r2dbc.SampleEntityRepository.SampleEntityWritingConverter;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactory;

@Configuration
public class R2dbcConfig extends AbstractR2dbcConfiguration {

	@Value("spring.r2dbc.url")
	private String r2dbcUrl;

	@Override
	public ConnectionFactory connectionFactory() {
		return ConnectionFactories.get(r2dbcUrl);
	}

	@Override
	protected List<Object> getCustomConverters() {
		return List
				.of(
						new SampleEntityReadingConverter(),
						new SampleEntityWritingConverter());
	}
}