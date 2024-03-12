# spring-addons-starter-openapi

The maintainer behind `springdoc-openapi` refuses to consider Spring (de)serialization specificities in his lib. He even deleted (not just closed) the issue #2494 created for that.

## Enum possible values
`springdoc-openapi` relies on `swagger-core` enums serialization to put possible values for enums in the spec. This isn't relevant because Spring never uses `swagger-core` to (de)serialize enumerated values. What Spring uses is:
- converters provided by the `FormattingConversionService` for `@RequestParam`, `@RequestHeader`, `@PathVariable`, `@MatrixVariable` and `@CookieValue`
- `HttpMessageConverter` to deserialize `@RequestBody` and serialize `@ResponseBody` in servlets
- `HttpMessageReader` (for `@RequestBody`) and `HttpMessageWriter` (for `@ResponseBody`) in reactive applications

What `spring-addons-starter-openapi` does is:
- scan the classpath to figure out if the app is a servlet or a reactive application
- pick the relevant Spring beans from the classpath to (de)serialize a given enum
- register a custom `ModelConverter` using Spring beans to have Swagger write the right serialized enum values in the OpenAPI spec

## Warning: this starter works only in servlets :/
Most of the work for reactive applications is done already, but the owner of this repo hasen't found (yet) a way to synchronize `HttpMessageWriter`.

If you find a way to get `SpringReactiveEnumModelConverter#toWrittingExtractor` to work ([fix the `FIXME` in it](https://github.com/ch4mpy/spring-addons/blob/dfbe20387ae7c423c103b6e5b6d853087473a537/spring-addons-starter-openapi/src/main/java/com/c4_soft/springaddons/openapi/SpringReactiveEnumModelConverter.java#L158)), feel free to send a PR ;)

To try your implementation, you can re-activate:
- the `springReactiveEnumModelConverter` bean in `src/main/java/com/c4_soft/springaddons/openapi/SpringAddonsOpenapiAutoConfiguration.java`
- the tests in `samples/enum-bug-reproducer-reactive/src/test/java/com/c4soft/EnumBugReproducerApplicationTests.java`
