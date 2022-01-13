#!/bin/sh

mvn deploy:deploy-file -Dfile=$1 -DrepositoryId=clojars -DpomFile=$2 -Durl=https://clojars.org/repo/
