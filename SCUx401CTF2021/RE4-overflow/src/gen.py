from random import randint

for i in range(100):
    a = randint(0, 31)
    b = randint(0, 31)
    print(f't=input[{a}];input[{a}]=input[{b}];input[{b}]=t;')