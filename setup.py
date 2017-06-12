from __future__ import absolute_import, division, print_function, unicode_literals

from setuptools import setup, find_packages
from setuptools.command.install import install
from codecs import open
from os import path
import subprocess

from jumper_ble_logger import version

here = path.abspath(path.dirname(__file__))


class InstallAgent(install):
    def run(self):
        install.run(self)
        result = subprocess.check_output(['bash', './setup_service.sh'])
        print('Result of setup_service.sh:')
        print(result)

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='jumper-ble-logger',
    version=version,

    cmdclass={'install': InstallAgent},
    description='Jumper GATT proxy for logging BLE traffic',
    long_description=long_description,

    # The project's main homepage.
    url='https://github.com/Jumperr-labs/jumper-ble-logger',
    download_url='https://github.com/Jumperr-labs/jumper-ble-logger/archive/{}.tar.gz'.format(version),

    # Author details
    author='Jumper Team',
    author_email='info@jumper.io',

    keywords=['ble', 'bluetooth', 'nrf52', 'gatt', 'logging', 'jumper'],
    license='Apache 2.0',

    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],


    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=find_packages(exclude=['tests']),
    install_requires=['construct', 'jumper-logging-agent'],
    extras_require={
        'dev': ['ipython', 'nose', 'pygatt']
    },
    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    entry_points={
        'console_scripts': [
            'jumper-ble-logger=jumper_ble_logger.ble_logger:main',
        ],
    },
)
