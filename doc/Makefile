all: doc

doc:
	mkdir -p dist/latest/
	cd ..
	lein codox

github: doc2
	ghp-import -m "Generate documentation" -b gh-pages dist/
	git push origin gh-pages
