(defproject buddy/buddy-core "0.4.2"
  :description "Security library for Clojure"
  :url "https://github.com/funcool/buddy-core"
  :license {:name "BSD (2-Clause)"
            :url "http://opensource.org/licenses/BSD-2-Clause"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [commons-codec/commons-codec "1.10"]
                 [org.bouncycastle/bcprov-jdk15on "1.52"]
                 [org.bouncycastle/bcpkix-jdk15on "1.52"]]
  :source-paths ["src"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :test-paths ["test"])
