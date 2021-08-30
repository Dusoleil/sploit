from os.path import join, dirname
libpath=join(dirname(__file__),"sploit")
__path__ = [libpath]
exec(open(join(libpath,"__init__.py")).read())
