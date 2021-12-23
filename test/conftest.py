import pytest


def pytest_addoption(parser):
	parser.addoption(
		"--build_path", action="store", default="../build", help="Provide absolute path of the build directory"
	)


@pytest.fixture
def build_path(request):
	return request.config.getoption("--build_path")