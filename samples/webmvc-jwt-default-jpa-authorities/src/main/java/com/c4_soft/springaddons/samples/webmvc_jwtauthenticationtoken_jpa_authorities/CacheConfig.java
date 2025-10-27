package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
public class CacheConfig {
	
	  @Bean
	  CacheManager cacheManager() {
	      return new ConcurrentMapCacheManager("users-authorities");
	  }

}