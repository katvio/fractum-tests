from pathlib import Path

from setuptools import find_packages, setup

from src.config import REQUIRED_PYTHON_VERSION, VERSION

# Find .whl files in the packages directory
packages_dir = Path("packages")
dependency_links = []
install_requires = []

if packages_dir.exists():
    for whl in packages_dir.glob("*.whl"):
        # Format: name-version-...whl
        name = whl.stem.split("-")[0]
        dependency_links.append(f"file:{whl}")
        install_requires.append(name)

setup(
    name="fractum",
    version=VERSION,
    packages=find_packages(),
    install_requires=install_requires,
    # The suites are plain unittest and run through tests/run_tests.py. Both
    # extras are optional: pytest is only needed to pick up tests/conftest.py,
    # which relaxes the runtime version guard on interpreters below the required
    # patch level, and hypothesis only drives tests/test_properties.py, which
    # skips itself when the package is absent.
    extras_require={"test": ["pytest", "hypothesis"]},
    dependency_links=dependency_links,
    setup_requires=["wheel"],
    entry_points={
        "console_scripts": [
            "fractum=src.__init__:cli",
        ],
    },
    python_requires=f"=={REQUIRED_PYTHON_VERSION[0]}.{REQUIRED_PYTHON_VERSION[1]}.{REQUIRED_PYTHON_VERSION[2]}",
)
