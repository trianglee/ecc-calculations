from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

with open('README.md') as f:
    long_description = f.read()

setup(
    name='ecc_calculations',
    version='0.0.1',
    description="Reference code for performing some ECC calculations directly with ECC operations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/trianglee/ecc-calculations",
    author="Nimrod Zimerman",
    author_email="zimerman@fastmail.fm",
    license="Apache License 2.0",
    packages=find_packages(),
    python_requires='>=3.7',
    install_requires=requirements,
)
