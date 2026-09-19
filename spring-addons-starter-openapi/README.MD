# spring-addons-starter-openapi

A single-purpose starter for [springdoc-openapi](https://springdoc.org/): it makes the **possible values of enums** in the generated OpenAPI spec match what a Spring application actually accepts and emits.

## Is it still needed?

Yes. The situation was re-checked against `springdoc-openapi` **2.8.x** on Spring Boot **3.5** (Jackson 2):

| Where the enum is used | What springdoc alone puts in the spec | What Spring actually does | Still a problem? |
|---|---|---|---|
| `@RequestBody` / `@ResponseBody` (JSON) | the `toString()` value, or `@JsonValue` if present (via `swagger-core`) | Jackson 2 defaults `WRITE_ENUMS_USING_TO_STRING` and `READ_ENUMS_USING_TO_STRING` to `false`, so it uses `name()` unless `@JsonValue` (or `@JsonProperty` on constants) is present | **Yes**, for any enum with a custom `toString()` and no `@JsonValue`: the spec advertises labels the application rejects. It also stays a problem when the application changes these features or uses another message converter: `swagger-core` never asks the application's converters. |
| `@RequestParam`, `@PathVariable`, `@RequestHeader`, `@CookieValue`, `@MatrixVariable` | the same `toString()` / `@JsonValue` value | the `ConversionService`: `Enum.valueOf(name())` unless a `Converter<String, E>` is registered | **Yes.** For any enum whose `toString()` (or `@JsonValue`) differs from `name()`, a client following the spec gets a `400` on every such parameter. springdoc's own `WebConversionServiceProvider` handling explicitly skips enums. |

So the starter is relevant as soon as your API has enums with a custom `toString()`, in **bodies** or in **parameters**. The original report was [springdoc-openapi#2494](https://github.com/springdoc/springdoc-openapi/issues/2494); the reproducer now lives in this module's tests (`src/test/java`, `EnumsApplication` and the `*EnumValuesTest` classes).

## What it does

It registers a Swagger `ModelConverter` bean (springdoc picks up any such bean) which, for enum types only, replaces `swagger-core`'s guess with values obtained from the application itself:

- **parameters** (`@RequestParam`, `@PathVariable`, `@RequestHeader`, `@CookieValue`, `@MatrixVariable`, detected from the annotations springdoc passes along): candidate value sets are tried in this order — what the HTTP message converters write, `toString()`, `name()` — and the first one that the application's `ConversionService` converts back to every constant is used. With Spring defaults that gives `name()`; with a registered `Converter<String, E>` it gives whatever that converter accepts.
- **bodies** (anything else, including DTO properties): each constant is serialized by the JSON `HttpMessageConverter`s of the `RequestMappingHandlerAdapter` (servlet) or the JSON `Encoder`s of the `ServerCodecConfigurer` (reactive), i.e. by exactly what Spring uses for `@RequestBody` / `@ResponseBody`. If several converters disagree, the spec generation fails with a message naming them (a spec can't describe both). If no converter is found, the springdoc `ObjectMapper` is used as a fallback.

Both servlet and reactive applications are supported (the reactive converter used to be disabled until now).

## Usage

```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-openapi</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
```

Nothing to configure. The auto-configuration only registers the converter matching the application type (servlet or reactive).

## Example

```java
public enum Status {
    ACTIVE("active"), CLOSED("closed");

    private final String label;
    Status(String label) { this.label = label; }

    @Override
    @JsonValue
    public String toString() { return label; }
}

@GetMapping("/accounts")
List<Account> list(@RequestParam Status status) { ... }   // Account has a Status property
```

| | `status` query parameter | `Account.status` property |
|---|---|---|
| springdoc alone | `["active", "closed"]` → `400`, Spring expects `ACTIVE` / `CLOSED` | `["active", "closed"]` |
| with this starter | `["ACTIVE", "CLOSED"]` | `["active", "closed"]` |

Register a `Converter<String, Status>` accepting the labels and the parameter values become `["active", "closed"]` too: the spec follows the application, not the other way around.
