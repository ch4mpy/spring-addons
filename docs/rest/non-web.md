---
title: Non-web applications
parent: spring-addons-starter-rest
nav_order: 4
description: "Using spring-addons-starter-rest in a batch or messaging application, without spring-boot-starter-web or spring-boot-starter-webflux on the classpath."
---

# Using `spring-addons-starter-rest` in a non-web application


As `spring-boot-starter-oauth2-client` auto-configures only Web applications, we must import `OAuth2ClientProperties` and declare an `OAuth2AuthorizedClientManager` bean:
```java
@Configuration
@Import(OAuth2ClientProperties.class)
public class SecurityConfiguration {

  @Bean
  ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties properties) {
    List<ClientRegistration> registrations = new ArrayList<>(
        new OAuth2ClientPropertiesMapper(properties).asClientRegistrations().values());
    return new InMemoryClientRegistrationRepository(registrations);
  }

  @Bean
  OAuth2AuthorizedClientService authorizedClientService(
      ClientRegistrationRepository clientRegistrationRepository) {
    return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
  }

  @Bean
  OAuth2AuthorizedClientManager authorizedClientManager(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientService authorizedClientService) {
    return new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository,
        authorizedClientService);
  }
}
```

In the same way, `spring-addons-starter-rest` post-processes the bean definition registry to add definitions for `RestClient`/`WebClient` (or builders) beans of Web application only. So, the following needs to be added to a servlet REST configuration for `RestClient` beans to be auto-configured:
```java
@Bean
SpringAddonsRestClientBeanDefinitionRegistryPostProcessor springAddonsRestClientBeanDefinitionRegistryPostProcessor(Environment environment) {
  return new SpringAddonsRestClientBeanDefinitionRegistryPostProcessor(environment);
}
```
To get `WebClient` beans, we should use `SpringAddonsServletWebClientBeanDefinitionRegistryPostProcessor` or `SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor` depending on the application being synchronized or reactive.

When using `SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor`, we must expose a `ReactiveOAuth2AuthorizedClientManager` instead of an `OAuth2AuthorizedClientManager`.
