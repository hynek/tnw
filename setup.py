# -*- coding: utf-8 -*-

from setuptools import setup


setup(
    name='tlsep',
    version='0.1',
    classifiers=["Private :: Do Not Upload"],
    entry_points={
        'console_scripts': [
            'tlsep = tlsep.__main__:main',
        ]
    },
    packages=[
        'tlsep',
    ],
    install_requires=[
        'getdns',
        'idna',
        'twisted',
    ],
)
