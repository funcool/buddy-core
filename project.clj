(defproject buddy/buddy-core "0.5.0"
  :description "Cryptographic Api for Clojure."
  :url "https://github.com/funcool/buddy-core"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [commons-codec/commons-codec "1.10"]
                 [org.bouncycastle/bcprov-jdk15on "1.52"]
                 [slingshot "0.12.2"]
                 [org.bouncycastle/bcpkix-jdk15on "1.52"]]
  :source-paths ["src"]
  :test-paths ["test"]
  :jar-exclusions [#"\.cljx|\.swp|\.swo|user.clj"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :profiles {:dev {:codeina {:sources ["src"]
                             :exclude [buddy.core.sign.impl]
                             :language :clojure
                             :output-dir "doc/api"
                             :src-dir-uri "http://github.com/funcool/buddy-core/blob/master/"
                             :src-linenum-anchor-prefix "L"}
                   :plugins [[funcool/codeina "0.1.0-SNAPSHOT"
                              :exclusions [org.clojure/clojure]]]}})

