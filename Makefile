clean:
	rm -rf ./.venv/
	rm -rf ./build/
	rm -rf ./dist/
	rm -rf ./$(NAME).egg-info/
	rm -rf ./py_$(NAME).egg-info/

check:
	uvx ruff format
	uvx ruff check
	uvx ty check

test:
	uv run pytest
