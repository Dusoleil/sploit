from setuptools import setup
setup(
        name='sploit',
        version='0',
        packages=['sploit'],
        entry_points={"console_scripts":["sploit=sploit.main:main"]}
     )
