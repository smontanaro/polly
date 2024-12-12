
all : doc lint

doc : README.html

README.html : README.md
	markdown_py < README.md > README.html

test : FORCE
	bash tests/runtests.sh -c

install : FORCE
	@echo "Use 'python -m build && python -m pip install ...'"

lint : FORCE
	pylint polly/*.py

FORCE :

.PHONY : doc all test install
