{:dev
 {:aliases {"test-all" ["with-profile" "dev,1.9:dev,1.8:dev,1.7:dev" "test"]}
  :plugins [[lein-ancient "0.7.0"]
            [lein-codox "0.10.7"]]
  :global-vars {*warn-on-reflection* true}
  :jvm-opts ^:replace []
  :dependencies
  [[org.clojure/tools.namespace "1.1.0"]
   [criterium/criterium "0.4.6"]
   [org.clojure/tools.reader "1.3.5"]
   [codox-theme-rdash "0.1.2"]]

  :codox {:project {:name "buddy-core"}
          :metadata {:doc/format :markdown}
          :output-path "doc/dist/latest/"
          :doc-paths ["doc/"]
          :themes [:rdash]
          :source-paths ["src"]
          :source-uri "https://github.com/funcool/buddy-core/blob/master/{filepath}#L{line}"
          :namespaces [#"^buddy\."]}}

 :1.9 {:dependencies [[org.clojure/clojure "1.9.0"]]}
 :1.8 {:dependencies [[org.clojure/clojure "1.8.0"]]}
 :1.7 {:dependencies [[org.clojure/clojure "1.7.0"]]}}
