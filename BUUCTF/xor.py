l = ['f',0xA,'k',0xC,'w','&','O','.','@',0x11,'x',0xD,'Z',';','U',0x11,'p',0x19,'F',0x1F,'v','"','M','#','D',0xE,'g',6,'h',0xF,'G','2','O']
for i in range(1, len(l)):
    if(isinstance(l[i], int)):
        l[i] = chr(l[i])
flag = 'f'
for i in range(1, len(l)):
    flag += chr(ord(l[i]) ^ ord(l[i-1]))
print(flag) # flag{QianQiuWanDai_YiTongJiangHu}