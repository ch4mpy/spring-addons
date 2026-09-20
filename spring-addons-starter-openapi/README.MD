# spring-addons-starter-openapi

A single-purpose starter for [springdoc-openapi](https://springdoc.org/): it makes the **possible values of enums** in the generated OpenAPI spec match what a Spring application actually accepts and emits.

```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-openapi</artifactId>
    <version>${springaddons.version}</version>
</dependency>
```

It registers a Swagger `ModelConverter` bean which, for enum types only, replaces the guess of `swagger-core` with values obtained from the application itself: the `ConversionService` for parameters, the HTTP message converters for bodies. Servlet and reactive applications are both supported.

The situation was re-checked against `springdoc-openapi` 3.1.1 on Spring Boot 4.1 with Jackson 3: enum **bodies** are no longer a problem with the default Jackson configuration, enum **parameters** still are. The original report was [springdoc-openapi#2494](https://github.com/springdoc/springdoc-openapi/issues/2494), and the reproducer lives in this module's tests.

[Complete documentation](https://ch4mpy.github.io/spring-addons/openapi/), including when the starter is still needed and what exactly it converts.
