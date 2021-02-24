.PHONY: venv

NAME    := minisign

venvdir := ./venv

all: venv

define make_venv
	python3 -m venv --prompt $(NAME) $(1)
	( \
		source $(1)/bin/activate; \
		pip install -U "."; \
		deactivate; \
	)
endef

venv:
	$(call make_venv,$(venvdir))

clean:
	rm -rf $(venvdir)/

test:
	python3 -m unittest
