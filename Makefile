
all : doc

doc : README.html

README.html : README.md
	markdown_py < README.md > README.html

test : FORCE
	bash tests/runtests.sh

FORCE :

.PHONY : doc all test
