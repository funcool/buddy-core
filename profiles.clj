{:dev
 {:aliases {"test-all" ["with-profile" "dev,1.8:dev" "test"]}
  :codeina {:sources ["src"]
            :exclude [buddy.core.sign.impl]
            :reader :clojure
            :target "doc/dist/latest/api"
            :src-uri "http://github.com/funcool/buddy-core/blob/master/"
            :src-uri-prefix "#L"}
  :plugins [[funcool/codeina "0.3.0"]
            [lein-ancient "0.6.7"]]}

 :1.8 {:dependencies [[org.clojure/clojure "1.8.0-beta2"]]}}

