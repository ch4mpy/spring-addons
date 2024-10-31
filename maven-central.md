# Maven-Central Reminders

Cheat-sheets for me when setting up a new development environment

## GPG Sign Key
``` bash
gpg --list-keys
# if key absent, then generate one with
gpg --gen-key
# publish public key to one of supported servers 
export GPG_PUB_KEY=(replace with "pub" key)
gpg --keyserver keyserver.ubuntu.com --send-keys $GPG_PUB_KEY
gpg --keyserver keys.openpgp.org --send-keys $GPG_PUB_KEY
gpg --keyserver pgp.mit.edu --send-keys $GPG_PUB_KEY
```


## ~/.m2/settings.xml
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
  <servers>
    <server>
      <!-- OSSRH Jira account -->
      <id>ossrh</id>
      <username>change-me with a value from https://oss.sonatype.org/#profile;User%20Token</username>
      <password>change-me with a value from https://oss.sonatype.org/#profile;User%20Token</password>
    </server>
  </servers>

  <profiles>
    <profile>
      <id>ossrh</id>
      <activation>
        <activeByDefault>true</activeByDefault>
      </activation>
      <properties>
        <gpg.executable>gpg</gpg.executable>
        <gpg.passphrase>${env.GPG_PWD}</gpg.passphrase><!-- password retrieved from environment variable -->
      </properties>
    </profile>
  </profiles>
</settings>
```

Add-opens for releasing with JDK 17:
`export JDK_JAVA_OPTIONS='--add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.text=ALL-UNNAMED --add-opens java.desktop/java.awt.font=ALL-UNNAMED'`
