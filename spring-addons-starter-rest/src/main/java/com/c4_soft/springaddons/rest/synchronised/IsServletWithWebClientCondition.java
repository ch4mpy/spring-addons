package com.c4_soft.springaddons.rest.synchronised;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * A conditon to apply &#64;Configuration only if an application is a servlet and if
 * {@link WebClient} is on the class-path
 * 
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class IsServletWithWebClientCondition extends AllNestedConditions {

  IsServletWithWebClientCondition() {
    super(ConfigurationPhase.PARSE_CONFIGURATION);
  }

  @ConditionalOnWebApplication(type = Type.SERVLET)
  static class IsServlet {
  }

  @ConditionalOnClass(WebClient.class)
  static class IsWebClientOnClasspath {
  }

}
