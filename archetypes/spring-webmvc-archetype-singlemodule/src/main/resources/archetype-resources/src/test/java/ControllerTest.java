package ${package};

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AutoConfigureSecurityAddons;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@WebMvcTest
@AutoConfigureSecurityAddons
@Import({ EnableSpringDataWebSupportTestConf.class })
public @interface ControllerTest {

}
