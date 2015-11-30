from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='sfcloudpassage',
      packages= ['sfcloudpassage'],
      version=version,
      description="A simple python interface to the CloudPassage API",
      long_description="""\
A simple python interface to the CloudPassage API to authenticate, authorize and perform API calls""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Sujith Katakam',
      author_email='sujith.katakam@citrix.com',
      url='',
      license='Citrix',
      py_modules=['sfcloudpassage'],
      include_package_data=True,
      install_requires=[
          'requests >= 2.1.0'
      ],
      )
