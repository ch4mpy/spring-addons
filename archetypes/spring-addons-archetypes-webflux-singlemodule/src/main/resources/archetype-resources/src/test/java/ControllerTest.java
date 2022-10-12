package ${package};

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.webflux.jwt.AutoConfigureAddonsWebSecurity;
import ${package}.security.SecurityConfiguration;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@AutoConfigureAddonsWebSecurity
@Import({ SecurityConfiguration.class, EnableSpringDataWebSupportTestConf.class })
public @interface ControllerTest {

}
