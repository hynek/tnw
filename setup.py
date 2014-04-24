# -*- coding: utf-8 -*-

from setuptools import setup


setup(
    name='dane_doctor',
    version='0.1',
    classifiers=["Private :: Do Not Upload"],
    entry_points={
        'console_scripts': [
            'danex = danex.__main__:main',
        ]
    },
    packages=[
        'danex',
    ],
    install_requires=[
        'getdns',
        'idna',
        'twisted',
    ],
)
