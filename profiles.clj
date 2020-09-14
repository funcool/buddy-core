{:dev
 {:aliases {"test-all" ["with-profile" "dev,1.9:dev,1.8:dev,1.7:dev" "test"]}
  :plugins [[lein-ancient "0.6.15"]]}
 :1.9 {:dependencies [[org.clojure/clojure "1.9.0"]]}
 :1.8 {:dependencies [[org.clojure/clojure "1.8.0"]]}
 :1.7 {:dependencies [[org.clojure/clojure "1.7.0"]]}


 :codox
 {:dependencies [[org.clojure/tools.reader "1.1.0"]
                 [codox-theme-rdash "0.1.2"]]
  :plugins [[lein-codox "0.10.7"]]
  :codox {:project {:name "buddy-core"}
          :metadata {:doc/format :markdown}
          :output-path "doc/dist/latest/api"
          :doc-paths ["doc/"]

          ;; :doc-files ["doc/00-introduction.md"
          ;;             "doc/01-hash.md"]
          :themes [:rdash]
          :source-paths ["src"]
          :source-uri "https://github.com/funcool/buddy-core/blob/master/{filepath}#L{line}"
          :namespaces [#"^buddy\.core\."]}}
 }
