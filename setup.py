from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='GluuOTP',
    version='1.0.0',

    description='Yubikey OTP Validataion Library for Gluu Server',
    long_description=long_description,
    url='https://github.com/GluuFederation/gluu-otp',
    author='Gluu',
    author_email='support@gluu.org',
    license='GPLv3',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        ],

    keywords='gluuotp yubikey validation otp',

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=['pycrypto', 'python-ldap'],

    extras_require={
        'dev': [],
        'test': ['nose', 'coverage'],
    },
)
