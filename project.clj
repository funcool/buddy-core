(defproject buddy/buddy-core "0.12.1"
  :description "Cryptographic Api for Clojure."
  :url "https://github.com/funcool/buddy-core"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.8.0" :scope "provided"]
                 [commons-codec/commons-codec "1.10"]
                 [org.bouncycastle/bcprov-jdk15on "1.54"]
                 [org.bouncycastle/bcpkix-jdk15on "1.54"]]
  :source-paths ["src"]
  :test-paths ["test"]
  :jar-exclusions [#"\.cljx|\.swp|\.swo|user.clj"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"])

