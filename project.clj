(defproject kixi/buddy-core "1.1.2-SNAPSHOT"
  :description "Cryptographic Api for Clojure."
  :url "https://github.com/funcool/buddy-core"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.9.0-alpha13" :scope "provided"]
                 [org.clojure/test.check "0.9.0" :scope "test"]
                 [commons-codec/commons-codec "1.10"]]
  :source-paths ["src"]
  :test-paths ["test"]
  :jar-exclusions [#"\.cljx|\.swp|\.swo|user.clj"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"])

