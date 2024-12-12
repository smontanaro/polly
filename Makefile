
all : doc lint

doc : README.html

README.html : README.md
	markdown_py < README.md > README.html

test : FORCE
	bash tests/runtests.sh

install : FORCE
	@echo "Use 'python -m build && python -m pip install ...'"

lint : FORCE
	pylint src/*.py

FORCE :

.PHONY : doc all test install
