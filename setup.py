
from setuptools import setup


setup(
    name='deproxy',
    version=open("VERSION").read().strip(),
    py_modules=['deproxy', ],
    license=open('LICENSE').read(),
    long_description=(open('README.rst').read() + '\n\n' +
                      open('HISTORY.rst').read()),
    install_requires=["requests"],
    author='izrik',
    author_email='izrik@izrik.com',
    url='https://github.com/izrik/deproxy',
    description='Python library for testing HTTP proxies.',
    classifiers=(
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ),
)
