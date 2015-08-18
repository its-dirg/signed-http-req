# pylint: disable=missing-docstring
from setuptools import setup, find_packages

setup(
    name='signed-http-req',
    description='Python implementation of Signed HTTP Requests for OAuth.',
    version='1.0',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    install_requires=['pyjwkest'],
    url='https://github.com/its-dirg/signed-http-req',
    author='DIRG',
    author_email='dirg@its.umu.se',
)
