from setuptools import setup
from glob import glob

setup(
    name="ReverseShell",
    version="0.1.0",
    py_modules=["ReverseShell"],
    install_requires=["PythonToolsKit"],
    author="Maurice Lambert",
    author_email="mauricelambert434@gmail.com",
    maintainer="Maurice Lambert",
    maintainer_email="mauricelambert434@gmail.com",
    description=(
        "This package implements an advanced reverse "
        "shell console (supports: TCP, UDP, IRC, HTTP and DNS)."
    ),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/mauricelambert/ReverseShell",
    project_urls={
        "Documentation": "https://mauricelambert.github.io/info/python/security/ReverseShell.html",
        "Executable": "https://mauricelambert.github.io/info/python/security/ReverseShell.pyz",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3.9",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Topic :: System :: Networking",
        "Natural Language :: English",
        "Operating System :: MacOS",
        "Topic :: Security",
    ],
    scripts=glob("clients/*.py"),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": ["ReverseShell = ReverseShell:main"],
    },
    keywords=[
        "ReverseShell",
        "terminal",
        "console",
        "netcat",
        "HTTP",
        "IRC",
        "DNS",
        "TCP",
        "UDP",
    ],
    platforms=["Windows", "Linux", "MacOS"],
    license="GPL-3.0 License",
)
