# Example Upstream

A very simple Django app where you can log in and save a note.

1. Install [uv](https://github.com/astral-sh/uv)
2. `uv sync`
3. `uv run python manage.py migrate` to create the SQLite database
4. `uv run python manage.py runserver` to run the server on `localhost:8001`.
