test: nosetests flake8

nosetests:
	@echo "==== Running nosetests ===="
	@bin/test

flake8:
	@echo "==== Running Flake8 ===="
	@bin/flake8 src
