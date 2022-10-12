package ${package};

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

import ${package}.security.SecurityConfig;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@AutoConfigureAddonsWebSecurity
@Import({ SecurityConfig.class, EnableSpringDataWebSupportTestConf.class })
public @interface ControllerTest {

}
