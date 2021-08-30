ENCODING = ''
def log(s):
    if ENCODING != '':
        s = s.decode(ENCODING)
    print(s)

