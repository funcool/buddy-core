#!/bin/sh
mvn deploy:deploy-file -Dfile=target/buddy-core.jar -DpomFile=pom.xml -DrepositoryId=clojars -Durl=https://clojars.org/repo/
