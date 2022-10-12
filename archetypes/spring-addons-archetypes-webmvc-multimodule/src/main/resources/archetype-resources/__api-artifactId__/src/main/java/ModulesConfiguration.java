package ${package};

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import ${package}.exceptions.CustomExceptionHandler;
import ${package}.jpa.PersistenceConfig;
import ${package}.security.SecurityConfig;

@Import({ CustomExceptionHandler.class, PersistenceConfig.class, SecurityConfig.class })
@Configuration
public class ModulesConfiguration {
}