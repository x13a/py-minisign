.PHONY: venv

NAME    := minisign
VENVDIR := ./venv

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
	$(call make_venv,$(VENVDIR))

clean:
	rm -rf $(VENVDIR)/
	rm -rf ./build/
	rm -rf ./dist/
	rm -rf ./$(NAME).egg-info/
	rm -rf ./py_$(NAME).egg-info/

test:
	python3 -m unittest
