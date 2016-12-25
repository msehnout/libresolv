import re

lines = [re.findall('([A-Z]*)\s+([0-9]+)\s+(.*)', line) for line in open('TYPE.txt')]
# print(lines)
types = [t[0] for t in lines if t != [] ]
# print(types)
for (name,num,comment) in types:
    print("/// " + comment)
    print(name + " = " + num + ",")

print("\n\n")

for (name,num,comment) in types:
    print(num + " => Ok(TYPE::" + name + "),")