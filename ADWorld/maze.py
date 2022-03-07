maze = '  *******   *  **** * ****  * ***  *#  *** *** ***     *********'
g = ''
s = ''
for i in range(0, len(maze)):
    g += maze[i]
    if (i+1)%8==0:
        g += s + '\n'
        s = ''
print(g)