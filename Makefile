
INSTDIR = $(HOME)/local/bin

all : doc

doc : README.html

README.html : README.md
	markdown_py < README.md > README.html

test : FORCE
	bash tests/runtests.sh

install : $(INSTDIR)/polly

$(INSTDIR)/polly : $(PWD)/src/polly.py
	rm -f $(INSTDIR)/polly
	cp -p src/polly.py $(INSTDIR)/polly
	chmod +x $(INSTDIR)/polly

FORCE :

.PHONY : doc all test install
