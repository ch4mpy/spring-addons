# spring-addons-starter-openapi

The maintainer behind `springdoc-openapi` refuses to consider Spring (de)serialization specificities in his lib (he even deleted the issue #2494 I created for that).

## Enum possible values
`springdoc-openapi` relies on `swagger-core` enums serialization to put possible values for enums in the spec. This isn't relevant because Spring never uses `swagger-core` to (de)serialize enumerated values. What Spring uses is:
- converters provided by the `FormattingConversionService` for `@RequestParam`, `@RequestHeader`, `@PathVariable`, `@MatrixVariable` and `@CookieValue`
- `HttpMessageConverter` to deserialize `@RequestBody` and serialize `@ResponseBody` in servlets
- `HttpMessageReader` (for `@RequestBody`) and `HttpMessageWriter` (for `@ResponseBody`) in reactive applications

What `spring-addons-starter-openapi` does is:
- scan the classpath to figure out if the app is a servlet or a reactive application
- pick the relevant Spring beans from the classpath to (de)serialize a given enum
- register a custom `ModelConverter` using Spring beans to have Swagger write the right serialized enum values in the OpenAPI spec

## Warning: The owner of this repo hasen't found (yet) a way to synchronize `HttpMessageWriter`. As a consequence, this starter works only in servlets :/
If you find a way to get `SpringReactiveEnumModelConverter#toWrittingExtractor` to work, feel free to feel a PR ;)

You can re-activate the tests in `samples/enum-bug-reproducer-reactive/src/test/java/com/c4soft/EnumBugReproducerApplicationTests.java` to try your implementation.