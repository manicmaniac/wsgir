from distutils.core import setup

setup(
    name='wsgir',
    version='0.0.1',
    description='Flaskr without Flask.',
    long_description=open('README.rst').read(),
    packages=['wsgir'],
    include_package_data=True,
)
