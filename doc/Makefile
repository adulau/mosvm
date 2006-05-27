mosvm-doc.tar.gz: vm-implementation.pdf vm-implementation.html
	tar -czvf mosvm-doc.tar.gz vm-implementation.pdf *.html *.css *.tex

vm-implementation.idx vm-implementation.pdf: vm-implementation.tex
	pdflatex vm-implementation
	pdflatex vm-implementation
	pdflatex vm-implementation
	makeindex vm-implementation.idx
	pdflatex vm-implementation

vm-implementation.html: vm-implementation.tex vm-implementation.idx
	tex2page vm-implementation.tex
	tex2page vm-implementation.tex

clean:
	rm -f *.ind *.aux *.log *.toc *.idx *.out *.ilg *.scm *.hlog
	rm -f vm-implementation.pdf *.html *.css
	
