#!/usr/bin/env python3
"""Package configuration."""
# fmt: off

import setuptools


setuptools.setup(
    name="ircstream",
    version="0.9.0",
    py_modules=["ircstream"],
    maintainer="Faidon Liambotis",
    maintainer_email="faidon@wikimedia.org",
    description="Wikimedia RC->IRC gateway",
    url="https://github.com/wikimedia/ircstream",
    license="Apache2",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Intended Audience :: System Administrators",
    ],
    keywords=["irc", "wikimedia"],
    python_requires=">=3.7",
    install_requires=[
        "prometheus_client",
        "structlog",
    ],
    entry_points={
        "console_scripts": [
            "ircstream = ircstream:main",
        ],
    },
    zip_safe=False,
)
