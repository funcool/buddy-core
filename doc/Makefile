all: doc2

doc:
	mkdir -p dist/latest/
	asciidoctor -o dist/latest/index.html content.adoc

doc2:
	mkdir -p dist/latest/
	cd ..
	lein with-profile +codox codox

github: doc2
	ghp-import -m "Generate documentation" -b gh-pages dist/
	git push origin gh-pages
