(defproject buddy/buddy-core "1.10.0"
  :description "Cryptographic Api for Clojure."
  :url "https://github.com/funcool/buddy-core"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.10.3" :scope "provided"]
                 [org.clojure/test.check "1.1.0" :scope "test"]
                 [commons-codec/commons-codec "1.15"]
                 [cheshire "5.10.0"]
                 [org.bouncycastle/bcprov-jdk15on "1.68"]
                 [org.bouncycastle/bcpkix-jdk15on "1.68"]]
  :jar-name "buddy-core.jar"
  :source-paths ["src"]
  :java-source-paths ["src"]
  :test-paths ["test"]
  :global-vars {*warn-on-reflection* true}
  :jar-exclusions [#"\.cljx|\.swp|\.swo|user.clj"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"])

