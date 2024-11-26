import os
from invoke import task
import pytest

@task(name="coverage")
def coverage(ctx):
    pytest.main(["--cov=eventrecorder_heroku_hook","--cov-report","html"])
    os.system("open htmlcov/index.html")
