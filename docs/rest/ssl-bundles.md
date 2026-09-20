---
title: SSL bundles
parent: spring-addons-starter-rest
nav_order: 3
description: "Using Spring Boot SSL bundles with an auto-configured RestClient or WebClient, including self-signed certificates and disabling certificate validation in development."
---

# Working with SSL bundles

`spring-addons-starter-rest` integrates with Spring Boot SSL bundles (introduced in Boot `3.1`). Lets consider the following Boot configurations for SSL with self signed certificates generated with `openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt -sha256 -days 3650 -passout pass:change-me -subj "/C=PY/ST=Tahiti/L=Papeete/CN=localhost/emailAddress=ch4mp@c4-soft.com"`:
- on the consumed REST API:
```yaml
server:
  port: 8081
  ssl:
    bundle: server
spring:
  ssl:
    bundle:
      pem:
        server:
          keystore:
            certificate: classpath:tls.crt
            private-key: classpath:tls.key
            private-key-password: change-me
```
- on the service using a REST client to call the service above:
```yaml
spring:
  ssl:
    bundle:
      pem:
        client:
          truststore:
            certificate: classpath:tls.crt
com:
  c4-soft:
    springaddons:
      rest:
        client:
          machin-client:
            base-url: https://localhost:8081
            ssl-bundle: client
```
In the configuration above:
- the same (self-signed) certificate is used to configure the `server` bundle on the consumed service, and the `client` bundle on the consuming side.
- the `server` SSL bundle is referenced in the `server.ssl.bundle` configuration of the consumed service
- the `client` SSL bundle is referenced in the `com.c4-soft.springaddons.rest.client` configuration of the consuming service

