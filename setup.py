from distutils.core import setup
# from distutils.core import setup, find_packages
# from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README'), encoding='utf-8') as f:
    long_description = f.read()
setup(name='pg_alert',
      version='2.0',
      py_modules=['pg_alert'],
      url='https://github.com/MichaelDBA/pg_alert',
      author='Michael Vitale',
      author_email='michael@sqlexec.com',
      description='a PG log alerting tool',
      package_data={'config': ['pg_alert.conf'], },
      classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
                  ],
      )
