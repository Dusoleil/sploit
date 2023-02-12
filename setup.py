from setuptools import setup, find_packages
setup(
        name='sploit',
        version='0.1',
        packages=find_packages(),
        entry_points={"console_scripts":["sploit=sploit.main:main"]}
     )
