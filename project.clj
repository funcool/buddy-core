(defproject buddy/buddy-core "0.3.0-SNAPSHOT"
  :description "Security library for Clojure"
  :url "https://github.com/niwibe/buddy"
  :license {:name "BSD (2-Clause)"
            :url "http://opensource.org/licenses/BSD-2-Clause"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.clojure/algo.monads "0.1.5"]
                 [commons-codec/commons-codec "1.10"]
                 [org.bouncycastle/bcprov-jdk15on "1.51"]
                 [org.bouncycastle/bcpkix-jdk15on "1.51"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"]
  :profiles {:speclj {:dependencies [[speclj "3.1.0"]]
                      :test-paths ["spec"]
                      :plugins [[speclj "3.1.0"]]}})
