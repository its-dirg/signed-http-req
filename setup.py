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
    license='Apache 2.0',
    author='DIRG',
    author_email='dirg@its.umu.se',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
