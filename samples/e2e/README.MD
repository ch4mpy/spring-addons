# End-to-end tests
Provides with live demos of a client interacting with running instances of authorization and resource servers.

I provide with `ActuatorApp`, a helper for programmatically running `spring-boot` apps which meet following requirements:
 - built as fat-jar: to be run as `java -jar ...`
 - pulls `spring-boot-starter-actuator` dependency: `health` end-point is used to ensure app is up before issuing requests and `shutdown` to ensure it is gently stopped
 
There is no need for managed apps to declare specific `management` configuration: `ActuatorApp` sets all it needs on `java -jar ...` command line

Tests run as follow:
 - when E2eTests configuration is loaded, two `ActuatorApp` instances are built.
   One for authorization-server and the second for resources-server, which triggers their packaging.
 - at the beginning of each test case, authorization and resource servers are (re)started with specific profiles
 - client requests are issued to the authorization-server to get access-tokens for various users
 - token format is checked to be in accordance with active profiles
 - few resource end-points are tried to demo resource-server behavior depending on the token subject and associated authorities.
   Reminder: 
    * when `authorities-claim` profiles is active, authorities are provided by authorization-server (in `authorities` claim) and solely `admin` user has authority to access `restricted` end-point
    * when `authorities-claim` profiles is not active, the resource-server manages authorities on his own and solely `jpa` user has authority to access `restricted` end-point