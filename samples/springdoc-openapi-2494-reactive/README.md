# Reproducer for [https://github.com/springdoc/springdoc-openapi/issues/2494](https://github.com/springdoc/springdoc-openapi/issues/2494)

considering the following enums:
```java
public static enum EnumSerializedByName {
    A("name a"),
    B("name b");

    String label;

    EnumSerializedByName(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        return label;
    }
}
```
```java
public static enum EnumSerializedByToString {
    A("str a"),
    B("str b");

    String label;

    EnumSerializedByToString(String label) {
        this.label = label;
    }

    @Override
    @JsonValue // Forces serialization using toString()
    public String toString() {
        return label;
    }
}
```
```java
public static enum BijectiveEnumSerializedByToString {
    A("bij a"),
    B("bij b");

    String label;

    BijectiveEnumSerializedByToString(String label) {
        this.label = label;
    }

    @Override
    @JsonValue // Forces serialization using toString()
    public String toString() {
        return label;
    }

    public static BijectiveEnumSerializedByToString fromString(String str) {
        for (final var e : BijectiveEnumSerializedByToString.values()) {
            if (Objects.equals(e.toString(), str)) {
                return e;
            }
        }
        return null;
    }

    @Component
    static class StringEnumSerializedByToStringConverter implements Converter<String, BijectiveEnumSerializedByToString> {
        @Override
        public BijectiveEnumSerializedByToString convert(String source) {
            return BijectiveEnumSerializedByToString.fromString(source);
        }
    }
}
```

with Spring default:
- `HttpMessageConverter` beans
- `Converter<String, EnumSerializedByName>`
- `Converter<String, EnumSerializedByToString>`

the generated spec is:
```json
  "components": {
    "schemas": {
      "Dto": {
        "required": ["bij", "name", "str"],
        "type": "object",
        "properties": {
          "name": { "type": "string", "enum": ["name a", "name b"] },
          "str": { "type": "string", "enum": ["str a", "str b"] },
          "bij": { "type": "string", "enum": ["bij a", "bij b"] }
        }
      }
    }
  }
```

This is:
- wrong for `EnumSerializedByName` wich is always serialized using `name()` and deserialised using `valueOf()`
- right for `BijectiveEnumSerializedByToString`
- right for `EnumSerializedByToString` when `HttpMessageConverter` beans are used (`@RequestBody` and `@ResponseBody`), but wrong when the default `Converter<String, EnumSerializedByToString>` is used (`@RequestParam`)
