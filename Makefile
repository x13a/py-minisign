.PHONY: build

NAME := minisign

clean:
	rm -rf ./.venv/
	rm -rf ./build/
	rm -rf ./dist/
	rm -rf ./$(NAME).egg-info/
	rm -rf ./py_$(NAME).egg-info/

format:
	uv run ruff format
	uv run ruff check --fix

check:
	uv run ruff format --check
	uv run ruff check
	uv run ty check

test:
	uv run pytest

build:
	uv build

sync:
	uv sync --group dev
