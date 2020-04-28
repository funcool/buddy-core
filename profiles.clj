{:dev
 {:aliases {"test-all" ["with-profile" "dev,1.9:dev,1.8:dev,1.7:dev" "test"]}
  :codeina {:sources ["src"]
            :reader :clojure
            :target "doc/dist/latest/api"
            :src-uri "http://github.com/funcool/buddy-core/blob/master/"
            :src-uri-prefix "#L"}
  :plugins [[funcool/codeina "0.5.0"]
            [lein-ancient "0.6.15"]]}
 :1.9 {:dependencies [[org.clojure/clojure "1.9.0"]]}
 :1.8 {:dependencies [[org.clojure/clojure "1.8.0"]]}
 :1.7 {:dependencies [[org.clojure/clojure "1.7.0"]]}}
