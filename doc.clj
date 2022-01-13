(require '[codox.main :as codox])

(codox/generate-docs
 {:output-path "doc/dist/latest"
  :metadata {:doc/format :markdown}
  :language :clojure
  :name "buddy/buddy-core"
  :themes [:rdash]
  :source-paths ["src"]
  :namespaces [#"^buddy\."]
  :source-uri "https://github.com/funcool/buddy-core/blob/master/{filepath}#L{line}"})
