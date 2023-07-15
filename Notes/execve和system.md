### execve

`execve()`函数有三个参数。

```c
int execve(const char *file,char *const argv[],char *const envp[])
```

第一个参数`file`是我们想要打开的二进制文件路径，可以填绝对路径或相对路径。

在说明第二个参数前，我们要说明一下`execve`函数的功能，众所周知程序是由进程执行的，但如果是使用`execve`函数的话，它能直接修改进程的函数内容，暂停执行该函数后面的全部代码，转头去执行第一个参数所指向的二进制文件。

第二个参数`argv[]`，它和主函数中的`argv[]`一致。

```c
int main(int argc,char* argv[])
```

第三个参数`envp[]`是环境变量表，通常是`NULL`。

在`pwn`中最常用的文件路径是`/bin/sh`和`/bin/cat`。一般最常用的是`execve("/bin/sh",0,0)`，此时`argv`为空会打开`shell`脚本解析器。我们可以写个`test.c`浅浅地测试一下：

```c
#include <unistd.h>

int main(int argc, char* argv[])
{
    execve("/bin/sh", 0, 0);
    return 0;
}
```

可以看到`execve("/bin/sh",0,0)`会直接打开`shell`脚本解析器。

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ gcc test.c -no-pie -o pwn

┌──(tyd㉿kali-linux)-[~/ctf]
└─$ ./pwn
$ cat flag
flag{t0ur1st}
```

接着来看看`argv`不为空的情况：

```c
#include <unistd.h>

int main()
{
    char *argv[] = {"/bin/sh", "flag", NULL};
    execve("/bin/sh", argv, 0);
    return 0;
}
```

可以看到当`char *argv[]={"/bin/sh","flag",NULL}`时，会把`flag`文件中的内容以报错的形式输出。如果题目把标准输入输出关闭时，我们用此方法依然可以拿到`flag`文件中的内容。

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ gcc test.c -no-pie -o pwn

┌──(tyd㉿kali-linux)-[~/ctf]
└─$ ./pwn
flag: 1: flag{t0ur1st}: not found
```

当文件路径是`/bin/cat`时，我们能这样打印出`flag`文件中的内容。

```c
#include <unistd.h>

int main()
{
    char *argv[] = {"/bin/cat", "flag", NULL};
    execve("/bin/cat", argv, 0);
    return 0;
}
```

测试结果如下：

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ gcc test.c -no-pie -o pwn
                                                                                                            
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ ./pwn
flag{t0ur1st}
```

------

### system

`system`函数的本质上是封装了`fork`和`execve`函数，调用时会自动创建子进程空间，并将新程序加载到子进程空间中运行起来。一般最常用的是`system("/bin/sh")`。

