# spring-rest-api-archetype
Maven archetype for Spring native REST API with webmvc, data-jpa, security (OpenID) and OpenAPI.

Please note a minimum of JDK 11 is required by spring-native.

# Sample usage
``` bash
# install the archetype
cd spring-rest-api-archetype
mvn install
cd ..

# generate a new project using the archetype
mvn archetype:generate \
  -DarchetypeGroupId=com.c4-soft.springaddons \
  -DarchetypeArtifactId=spring-webmvc-archetype \
  -DarchetypeVersion=3.1.16-jdk11 \
  -DgroupId=com.c4-soft \
  -DartifactId=bao-loc \
  -Dversion=1.0.0-SNAPSHOT

cd bao-loc

# generate OpenAPI spec
mvn clean install -Popenapi -DskipTests

# run
mvn spring-boot:run -pl sample-api

# generate regular (JVM) docker image
mvn clean package -Pbuild-image

# generate native docker image
mvn clean package -Pbuild-native-image -DskipTests
docker run --rm -p 8080:8080 -t sample-api:1.0.0-SNAPSHOT
```