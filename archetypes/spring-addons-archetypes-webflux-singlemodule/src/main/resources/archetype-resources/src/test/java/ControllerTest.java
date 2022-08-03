package ${package};

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.webflux.AutoConfigureSecurityAddons;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@WebFluxTest
@AutoConfigureSecurityAddons
@Import({ EnableSpringDataWebSupportTestConf.class })
public @interface ControllerTest {

}
