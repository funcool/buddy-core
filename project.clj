(defproject buddy/buddy-core "0.7.0"
  :description "Cryptographic Api for Clojure."
  :url "https://github.com/funcool/buddy-core"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.7.0" :scope "provided"]
                 [commons-codec/commons-codec "1.10"]
                 [org.bouncycastle/bcprov-jdk15on "1.52"]
                 [org.bouncycastle/bcpkix-jdk15on "1.52"]]
  :source-paths ["src"]
  :test-paths ["test"]
  :jar-exclusions [#"\.cljx|\.swp|\.swo|user.clj"]
  :javac-options ["-target" "1.7" "-source" "1.7" "-Xlint:-options"]
  :profiles {:dev {:codeina {:sources ["src"]
                             :exclude [buddy.core.sign.impl]
                             :reader :clojure
                             :target "doc/dist/latest/api"
                             :src-uri "http://github.com/funcool/buddy-core/blob/master/"
                             :src-uri-prefix "#L"}
                   :plugins [[funcool/codeina "0.3.0" :exclusions [org.clojure/clojure]]
                             [lein-ancient "0.6.7"]]}})

