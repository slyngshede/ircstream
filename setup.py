#!/usr/bin/env python3
"""Package configuration."""

import setuptools  # type: ignore


with open("README.md", "r") as readme:
    LONG_DESCRIPTION = readme.read()


setuptools.setup(
    name="ircstream",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    version="0.9.0",
    py_modules=["ircstream"],
    maintainer="Faidon Liambotis",
    maintainer_email="faidon@wikimedia.org",
    description="MediaWiki RC->IRC gateway",
    url="https://github.com/wikimedia/ircstream",
    license="Apache2",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Intended Audience :: System Administrators",
    ],
    keywords=["irc", "mediawiki", "wikimedia"],
    python_requires=">=3.7",
    # fmt: off
    install_requires=[
        "prometheus_client",
        "structlog",
    ],
    entry_points={
        "console_scripts": [
            "ircstream = ircstream:main",
        ],
    },
    # fmt: on
    zip_safe=False,
)
