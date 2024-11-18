.PHONY: venv
NAME    := minisign
venvdir := ./venv

all: venv

define make_venv
	python3 -m venv --prompt $(NAME) $(1)
	( \
		source $(1)/bin/activate; \
		pip install -U pip; \
		pip install -U "."; \
		deactivate; \
	)
endef

venv:
	$(call make_venv,$(venvdir))

clean:
	rm -rf $(venvdir)/
	rm -rf ./build/
	rm -rf ./dist/
	rm -rf ./minisign.egg-info/
	rm -rf ./py_minisign.egg-info/

test:
	python3 -m unittest
