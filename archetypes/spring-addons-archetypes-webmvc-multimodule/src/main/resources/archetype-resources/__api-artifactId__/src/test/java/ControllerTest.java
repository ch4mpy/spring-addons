package ${package};

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsSecurityWebmvcJwt;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@WebMvcTest
@AutoConfigureAddonsSecurityWebmvcJwt
@Import({ SampleApi.WebSecurityConfig.class, EnableSpringDataWebSupportTestConf.class })
public @interface ControllerTest {

}
