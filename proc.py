from pybasics import *


lst = read_file('lst', True)

for fname in lst:
    try:
        content = read_file(fname)

        if '52921' in content and 'build' not in fname and fname != 'lst':
            lines = [x for x in content.splitlines() if '5202' in x]
            for x in lines:
                if len(x) < 100:
                    print(fname, x)
    except:
        pass
