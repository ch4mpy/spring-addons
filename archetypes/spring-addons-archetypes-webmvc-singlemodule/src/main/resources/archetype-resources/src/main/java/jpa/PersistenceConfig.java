package ${package}.jpa;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import ${package}.domain.SampleEntity;

@EnableJpaRepositories()
@EntityScan(basePackageClasses = { SampleEntity.class })
@EnableTransactionManagement
public class PersistenceConfig {
}