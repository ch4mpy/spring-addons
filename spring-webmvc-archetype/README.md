# spring-rest-api-archetype
Maven archetype for Spring native REST API with webmvc, data-jpa, security (OpenID) and OpenAPI.

It is intended to be extended with one maven module per Spring `@RestController`: an higher number of micro-service applications allows great control over overall scallability and availability.

Please note a minimum of JDK 11 is required by spring-native.

# Sample usage
``` bash
# generate a new project using the archetype
mvn archetype:generate \
  -DarchetypeCatalog=remote \
  -DarchetypeGroupId=com.c4-soft.springaddons \
  -DarchetypeArtifactId=spring-webmvc-archetype \
  -DarchetypeVersion=3.1.17-jdk11 \
  -DgroupId=com.c4-soft \
  -DartifactId=bao-loc \
  -Dversion=1.0.0-SNAPSHOT \
  -Dapi-artifactId=solutions-api \
  -Dapi-path=solutions

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

If you ever wanted to use a snapshot, clone this repo, edit the archetype and then run:
``` bash
# install the archetype
cd spring-rest-api-archetype
mvn install
cd ..

# generate a new project using the local SNAPSHOT
mvn archetype:generate \
  -DarchetypeCatalog=local \
  -DarchetypeGroupId=com.c4-soft.springaddons \
  -DarchetypeArtifactId=spring-webmvc-archetype \
  -DarchetypeVersion=3.1.18-jdk11-SNAPSHOT \
  -DgroupId=com.c4-soft \
  -DartifactId=bao-loc \
  -Dversion=1.0.0-SNAPSHOT
```