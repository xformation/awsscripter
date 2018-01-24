#!/usr/bin/env python
# -*- coding: utf-8 -*-

from awsscripter import __version__
from setuptools import setup

with open("README.rst") as readme_file:
    readme = readme_file.read()

with open("HISTORY.rst") as history_file:
    history = history_file.read()

install_requirements = [
    "boto3>=1.3.0,<1.5.0",
    "click==6.6",
    "PyYaml==3.12",
    "Jinja2==2.8",
    "packaging==16.8",
    "colorama==0.3.7",
    "six==1.11.0"
]

test_requirements = [
    "pytest>=3.2",
    "troposphere>=2.0.0",
    "moto==0.4.31",
    "mock==2.0.0",
    "behave==1.2.5",
    "freezegun==0.3.9"
]

setup_requirements = [
    "pytest-runner>=3"
]

setup(
    name="awsscripter",
    version=__version__,
    description="Cloud Provisioning Tool",
    long_description=readme,
    author="Cloudreach",
    author_email="awsscripter@cloudreach.com",
    license='Apache2',
    url="https://github.com/cloudreach/awsscripter",
    packages=[
        "awsscripter",
        "awsscripter/resolvers",
        "awsscripter/hooks",
        "awsscripter/cli"
    ],
    package_dir={
        "awsscripter": "awsscripter"
    },
    py_modules=["awsscripter"],
    entry_points={
        "console_scripts": [
            'awsscripter = awsscripter.cli:cli'
        ],
        "awsscripter.hooks": [
            "asg_scheduled_actions ="
            "awsscripter.hooks.asg_scaling_processes:ASGScalingProcesses",
            "cmd = awsscripter.hooks.cmd:Cmd"
        ],
        "awsscripter.resolvers": [
            "environment_variable ="
            "awsscripter.resolvers.environment_variable:EnvironmentVariable",
            "file_contents = awsscripter.resolvers.file_contents:FileContents",
            "stack_output = awsscripter.resolvers.stack_output:StackOutput",
            "stack_output_external ="
            "awsscripter.resolvers.stack_output:StackOutputExternal"
        ]
    },
    data_files=[
        ("awsscripter/stack_policies", [
            "awsscripter/stack_policies/lock.json",
            "awsscripter/stack_policies/unlock.json"
        ])
    ],
    include_package_data=True,
    zip_safe=False,
    keywords="awsscripter",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Environment :: Console",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6"
    ],
    test_suite="tests",
    install_requires=install_requirements,
    tests_require=test_requirements,
    setup_requires=setup_requirements,
    extras_require={
        "test": test_requirements
    }
)
