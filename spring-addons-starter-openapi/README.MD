# spring-addons-starter-openapi

[The maintainer behind `springdoc-openapi` refuses to consider Spring (de)serialization specificities in his lib](https://github.com/springdoc/springdoc-openapi/issues/2494#issuecomment-1984288509). Until he changes his mind, this Spring Boot starter can be useful to register some beans to patch the OpenAPI spec generation in Spring apps.

## Enum possible values
`springdoc-openapi` relies on `swagger-core` enums serialization to put possible values for enums in the spec. This isn't relevant because Spring never uses `swagger-core` to (de)serialize enumerated values. What Spring uses is:
- `Converter<String, E>` to deserialize `@RequestParam` in servlets, the default converter always using enum `name()`, but an app can register custom converter beans to uses something else
- `HttpMessageConverter` to deserialize `@RequestBody` and serialize `@ResponseBody` in servlets, the default being `MappingJackson2HttpMessageConverter`
- `Encoder` and `Decoder` in reactive applications

What `spring-addons-starter-openapi` does is:
- scan the classpath to figure out if the app is a servlet or a reactive application
- pick the relevant Spring beans from the classpath to (de)serialize a given enum
- register a custom `ModelConverter` using Spring beans to have Swagger write the right serialized enum values in the OpenAPI spec

