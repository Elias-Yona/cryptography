from setuptools import setup, find_packages

setup(
    name='cryptography',
    version='0.1',
    description='A package for various cryptographic algorithms',
    author='Elias Yona',
    author_email='test@test.com',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'sha1=crypto.sha1.main:main'
        ],
    },
    install_requires=[
       
    ],
    tests_require=[
        'pytest',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
