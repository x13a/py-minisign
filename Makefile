clean:
	rm -rf ./.venv/
	rm -rf ./build/
	rm -rf ./dist/
	rm -rf ./$(NAME).egg-info/
	rm -rf ./py_$(NAME).egg-info/

test:
	uv run pytest
