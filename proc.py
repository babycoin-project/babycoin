from pybasics import *


lst = read_file('lst', True)

for fname in lst:
    try:
        content = read_file(fname)

        if 'nazi' in content and 'build' not in fname and fname != 'lst':
            lines = [x for x in content.splitlines() if 'Evolution' in x]
            for x in lines:
                print(fname, x)
    except:
        pass
