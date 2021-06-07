from random import randint
from hashlib import md5
from binascii import b2a_hex

def gen_random_direction():
    charset = '1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM'
    sel = []
    while len(sel) != 4:
        c = charset[randint(0,len(charset) - 1)]
        if c not in sel:
            sel.append(c)
    return {'U': sel[0], 'L': sel[1], 'R': sel[2], 'D': sel[3]}

def insert_rdrand():
    if randint(0,1) == 0:
        return '\t' + r'asm("push %rax");asm("rdrand %rax");asm("pop %rax");' + '\n'
    else:
        return ''

def gen_maze(w, h, steps):
    start_x = randint(0,w - 1)
    start_y = randint(0,h - 1)
    path = ''
    x = start_x
    y = start_y
    nodes = [(x, y)]
    direction = gen_random_direction()
    for i in range(steps):
        choices = []
        if y > 0 and (x, y - 1) not in nodes and (x - 1, y - 1) not in nodes and (x + 1, y - 1) not in nodes and (x, y - 2) not in nodes:
            choices.append(direction['U'])
        if x > 0 and (x - 1, y) not in nodes and (x - 1, y - 1) not in nodes and (x - 1, y + 1) not in nodes and (x - 2, y) not in nodes:
            choices.append(direction['L'])
        if x < w - 1 and (x + 1, y) not in nodes and (x + 2, y) not in nodes and (x + 1, y + 1) not in nodes and (x + 1, y - 1) not in nodes:
            choices.append(direction['R'])
        if y < h - 1 and (x, y + 1) not in nodes and (x + 1, y + 1) not in nodes and (x - 1, y + 1) not in nodes and (x, y + 2) not in nodes:
            choices.append(direction['D'])
        if len(choices) == 0:
            return gen_maze(w, h, steps)
        choice = choices[randint(0,len(choices) - 1)]
        path += choice
        if choice == direction['U']:
            y -= 1
        elif choice == direction['L']:
            x -= 1
        elif choice == direction['R']:
            x += 1
        elif choice == direction['D']:
            y += 1
        nodes.append((x, y))
    maze = ['*'] * (w * h)
    for node in nodes:
        maze[node[1] * w + node[0]] = '.'
    maze = ''.join(maze)
    return direction, start_x, start_y, maze, path

w = 25
h = 25
steps = 15
out = '#include <cstdio>\n#include <cstdlib>\n\n'
mazen = 100
all_path = ''

for i in range(mazen):
    out += f'void maze_{i + 1}'
    out += '(){\n'
    direction, start_x, start_y, maze, path = gen_maze(w, h, steps)
    mask = [randint(1, 0xFF) for i in range(len(maze))]
    for j in range(len(maze)):
        m = maze[j]
        out += f'\tunsigned char m_{j} = {ord(m) ^ mask[j]};\n'
        out += insert_rdrand()
        '''
        char direction[4] = {U,D,L,R};
        unsigned char *maze = &m_1;
        int x = start_x, y = start_y, last_x = start_x, last_y = start_y, last_last_x, last_last_y;
        for(int i = 0;i < steps;i ++){
            last_last_x = x, last_last_y = y;
            char c = getchar();
            if(c == direction[0]) y -= 1;
            else if(c == direction[1]) y += 1;
            else if(c == direction[2]) x -= 1;
            else if(c == direction[3]) y += 1;
            else exit(0);
            if(x < 0 || y < 0 || x >= w || y >= h || maze[w * y + x] != '.' || (x == last_x && y == last_y)) exit(0);
            last_x = last_last_x, last_y = last_last_y;
        }
        '''
    out += f'\tint mask[{len(maze)}] = {{'
    for j in range(len(maze)):
        out += f'{mask[j]}, '
    out += '};\n'
    out += f'\tchar dU = \'{direction["U"]}\', dD = \'{direction["D"]}\', dL = \'{direction["L"]}\', dR = \'{direction["R"]}\';\n'
    out += '\tunsigned char *maze = &m_0;\n'
    out += f'\tint x = {start_x}, y = {start_y}, last_x = {start_x}, last_y = {start_y}, last_last_x, last_last_y;\n'
    out += f'\tfor(int i = 0;i < {steps};i ++){{\n'
    out += f'\t\tlast_last_x = x, last_last_y = y;\n'
    out += '\t\tchar c = getchar();\n'
    out += '\t\tif(c == dU) y -= 1;\n'
    out += '\t\telse if(c == dD) y += 1;\n'
    out += '\t\telse if(c == dL) x -= 1;\n'
    out += '\t\telse if(c == dR) x += 1;\n'
    out += '\t\telse exit(0);\n'
    out += f'\t\tif(x < 0 || y < 0 || x >= {w} || y >= {h} || (maze[{w} * y + x] ^ mask[{w} * y + x]) != 46  || (x == last_x && y == last_y)) exit(0);\n'
    out += '\t\tlast_x = last_last_x, last_y = last_last_y;\n'
    out += '\t}\n'
    out += '}\n\n'
    all_path += path

out += 'int main(){\n'
for i in range(mazen):
    out += f'\tprintf("Maze-{i+1}\\nPlease input the escape route: ");\n'
    out += f'\tmaze_{i+1}();\n'
out += '\tprintf("Great!\\n");\n'
out += '\tprintf("Define d as the md5 digest of your input(1500 bytes in total)\\n");\n'
out += '\tprintf("Here is your flag(UUID format): flag{d[0:8]-d[8:12]-d[12:16]-d[16:20]-d[20:32]}\\n");\n'
out += '}\n'
print(all_path)
print(f'flag=flag{{{b2a_hex(md5(all_path.encode()).digest()).decode()}}}')

with open('100mazes.cpp', 'w') as f:
    f.write(out)
