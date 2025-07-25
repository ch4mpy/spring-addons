package com.c4_soft.springaddons.rest;

import org.springframework.beans.factory.FactoryBean;
import org.jspecify.annotations.Nullable;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.invoker.HttpExchangeAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import lombok.NoArgsConstructor;

/**
 * Bean factory using {@link HttpServiceProxyFactory} to generate an instance of a
 * {@link HttpExchange &#64;HttpExchange} interface
 * 
 * @param <T> {@link HttpExchange &#64;HttpExchange} interface to implement
 * @see RestClientHttpExchangeProxyFactoryBean RestClientHttpExchangeProxyFactoryBean for an
 *      equivalent accepting only RestClient
 * @see HttpExchangeProxyFactoryBean HttpExchangeProxyFactoryBean for an equivalent accepting both
 *      RestClient an WebClient
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@NoArgsConstructor
public class WebClientHttpExchangeProxyFactoryBean<T> implements FactoryBean<T> {
  private Class<T> httpExchangeClass;
  private HttpExchangeAdapter adapter;

  public WebClientHttpExchangeProxyFactoryBean(Class<T> httpExchangeClass, WebClient client) {
    this.httpExchangeClass = httpExchangeClass;
    this.setClient(client);
  }

  @Override
  @Nullable
  public T getObject() throws Exception {
    if (adapter == null || getObjectType() == null) {
      throw new RestMisconfigurationException(
          "Both of a WebClient and the @HttpExchange interface to implement must be configured on the HttpExchangeProxyFactoryBean before calling the getObject() method.");
    }
    return HttpServiceProxyFactory.builderFor(adapter).build().createClient(getObjectType());
  }

  @Override
  public Class<T> getObjectType() {
    return httpExchangeClass;
  }

  public WebClientHttpExchangeProxyFactoryBean<T> setHttpExchangeClass(Class<T> httpExchangeClass) {
    this.httpExchangeClass = httpExchangeClass;
    return this;
  }

  public WebClientHttpExchangeProxyFactoryBean<T> setClient(WebClient client) {
    this.adapter = WebClientAdapter.create(client);
    return this;
  }

}
