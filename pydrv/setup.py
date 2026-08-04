import os
from setuptools import find_packages, setup


def list_files(d):
    fs = []
    for root, dirs, files in os.walk(d):
        for f in files:
            fs.append(os.path.join(root, f))
    return fs


setup(
    name="tudor",
    version="1.0.0",
    packages=find_packages(),
    package_data={
        "": list_files("%s/tudor" % os.path.dirname(os.path.realpath(__file__)))
    },
    python_requires=">3",
    install_requires=["cryptography", "pyusb", "matplotlib"],
    entry_points={"console_scripts": ["tudor-safe=tudor.safe_cli:main"]},
)
