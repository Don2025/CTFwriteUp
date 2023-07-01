## [Angr](https://github.com/angr/angr)

### 前言

` angr` 是加州大学圣芭芭拉分校基于` Python`设计的，它是一个基于符号执行和模拟执行的、支持多架构的二进制分析框架，具备对二进制文件的动态符号执行能力和多种静态分析能力，可以在很多的场景使用，比如在逆向分析中可以使用`angr`动态符号执行解出`flag`，在漏洞挖掘中也可以使用`angr`对程序脆弱性的分析。

- angr来源于CGC项目，最初用于自动攻防。
- angr是平台无关（platform-agnostic）的二进制分析框架
- 可以用于
    - Disassembly and intermediate-representation lifting
    - Program instrumentation
    - **Symbolic execution**
        - 符号执行是一种程序分析技术，可以通过分析程序来得到让特定代码区域执行的输入。
        - 使用符号执行分析一个程序时，该程序会使用符号值来替代具体值作为输入。在达到目标代码时，分析器可以得到相应的路径约束，然后通过约束求解器来得到可以触发目标代码的具体值。
        - 符号执行相较于真实值执行的优点在于，当使用真实值执行程序时，我们能够遍历的程序路径只有一条，而使用符号进行执行时，由于符号是可变的，我们就可以利用这一特性，尽可能地将程序的每一条路径遍历，这样的话，必定存在至少一条能够输出正确结果的分支，每一条分支的结果都可以表示为一个离散关系式，使用约束求解引擎即可分析出正确结果。
    - Control-flow analysis
    - Data-dependency analysis
    - Value-set analysis (VSA)

### 服务器配置Jupyter Notebook

已经安装了`Python`，且更喜欢手动管理软件包，可以不用安装`Anaconda`，直接`pip`安装`Jupyter`。

```bash
pip3 install jupyter
```

打开`ipython`生成密钥。

```bash
ipython
```

输入以下代码以及两次密码即可生成密钥。

```python
In [1]: from notebook.auth import passwd                                        
In [2]: passwd()         
Enter password: 
Verify password: 
Out[2]: 'sha1:salt:hashed-password'
 
In [3]: exit()
```

生成配置文件。

```bash
jupyter notebook --generate-config
```

修改配置文件。

```bash
vim /root/.jupyter/jupyter_notebook_config.py
```

 用 **/** 查找内容并修改注释为以下内容然后**:wq**保存退出即可。字符串前加'u'表示后面的字符串以Unicode格式进行编码，防止因为字符串存储格式不同而导致解析出错。

```bash
c.NotebookApp.allow_remote_access = True   # 允许外部访问
c.NotebookApp.ip='*'                       # 设置所有ip皆可访问
c.NotebookApp.password = u'sha1:salt:hashed-password'  # 刚才生成的密钥'
c.NotebookApp.open_browser = False       # 禁止自动打开浏览器
c.NotebookApp.port = 2021                # 任意指定一个不冲突的端口
c.NotebookApp.notebook_dir = '/home/ubuntu/JupyterProject/' #默认文件路径
c.NotebookApp.allow_root = True          # 允许root身份运行jupyter notebook
```

除了在阿里云官网控制台的安全组中添加相应端口外，还要在云服务器中也相应地开放端口。

```bash
sudo su root
ufw allow 8888
ufw reload
ufw status
```

运行`jupyter notebook`，如果上面设置中没有允许`root`身份但此时是用`root`身份运行`jupyter`的话，记得添加参数`--allow-root`，此时在云服务器本机是可以访问的，外网也可以访问。

```bash
jupyter notebook
```

### 安装Angr

安装一些依赖包。

```bash
sudo apt-get update --fix-missing
sudo apt-get install python3-dev libffi-dev build-essential virtualenvwrapper
```

直接 `pip` 安装 `angr` 的话会在 `import` 时报错，所以应该使用 `virtualenv` 来进行安装，我使用了以下命令行进行安装。

```bash
virtualenv angr && pip install angr && source ./angr/bin/activate
# z3包 pip install 安装速度过慢可以临时切换清华源 python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple angr
```

此外，如果不使用`virtualenv`来创建虚拟环境的话，用`conda`也可以。

```bash
conda create -n angr
conda activate angr
pip install angr
```

`angr`官方推荐使用虚拟环境运行，每次需要调用具有`angr`环境时，只需要执行：

```shell
mkvirtualenv --python=$(which python3) angr
```

##### 如果遇上 mkvirtualenv: command not found 问题

- 在终端命令行输入以下命令：

    - `sudo pip install virtualenv`
    - `sudo pip install virtualenvwrapper`

- 没问题下一步

    - `cd ~/`

- 找到virtualenvwrapper.sh所在的位置

    - ```bash
        ┌──(tyd㉿kali-linux)-[~/ctf]
        └─$ find / -name 'virtualenvwrapper.sh'
        /usr/share/virtualenvwrapper/virtualenvwrapper.sh
        ```

- 修改`~/.bashrc`文件

    - `vim ~/.bashrc`
    - 在文件末尾添加两行代码
        - `export WORKON_HOME=~/.environments`
        - `source /usr/share/virtualenvwrapper/virtualenvwrapper.sh`

- 保存退出即可

- 重新加载`~/.bashrc`文件

    - `source ~/.bashrc`

### Jupyter Notebook 切换至虚拟环境

我的`angr`虚拟环境是安装在`Jupyter Notebook`根目录下的，安装`ipykernel`添加当前的`angr`环境至`Jupyter Notebook`。

```bash
source ./angr/bin/activate
pip3 install ipykernel
python -m ipykernel install --name angr
```

### 使用方法 （待完善）

[**angr API documentation**](https://api.angr.io)

`angr` 的使用步骤大致如下：

- 创建 `Project` 对象，将一个二进制文件加载到分析平台。

    ```python
    >>> import angr
    >>> proj = angr.Project('./baby_reverse')
    ```

     `Project` 是angr中控制基础，

-  `Project` 有一些基础属性。

    ```python
    
    >>> proj.entry # 二进制文件的入口地址
    0x4010a0
    >>> proj.filename # 文件名
    './baby_reverse'
    ```

- `arch`

    ```python
    >>> import monkeyhex
    >>> arch = proj.arch  # 架构
    >>> arch
    <Arch AMD64 (LE)>
    >>> arch.name
    'AMD64'
    >>> arch.bits
    0x40
    >>> arch.bytes
    0x8
    >>> arch.vex_arch
    'VexArchAMD64'
    >>> arch.qemu_name
    'x86_64'
    >>> arch.ida_processor
    'metapc'
    >>> arch.triplet
    'x86_64-linux-gnu'
    >>> arch.max_inst_bytes
    0xf
    >>> arch.ip_offset
    0xb8
    >>> arch.sp_offset
    0x30
    >>> arch.bp_offset
    0x38
    >>> arch.lr_offset
    >>> arch.vex_conditional_helpers
    True
    >>> arch.syscall_num_offset
    0x10
    >>> arch.call_pushes_ret
    True
    >>> arch.stack_change
    -0x8
    >>> arch.memory_endness
    'Iend_LE'
    >>> arch.register_endness
    'Iend_LE'
    >>> arch.instruction_endness
    'Iend_BE'
    >>> arch.sizeof
    {'short': 0x10, 'int': 0x20, 'long': 0x40, 'long long': 0x40}
    ```

- 设置 `state` 

- loader
  
  ```python
  >>> loader = proj.loader
  >>> loader
  <Loaded baby_reverse, maps [0x400000:0xb07fff]>
  >>> loader.main_object # Project加载的二进制文件信息 名字 映射地址
  <ELF Object baby_reverse, maps [0x400000:0x40407f]>
  >>> loader.main_object.pic # 查询主对象是否开启了PIC
  True
  >>> loader.main_object.execstack # 查询主对象是否开启了NX 栈是否可执行
  False
  >>> loader.shared_objects # 共享目标文件的信息 名字 映射地址 
  OrderedDict([('baby_reverse', <ELF Object baby_reverse, maps [0x400000:0x40407f]>), ('libc.so.6', <ELF Object libc.so.6, maps [0x500000:0x727e4f]>), ('ld-linux-x86-64.so.2', <ELF Object ld-linux-x86-64.so.2, maps [0x800000:0x83b2d7]>), ('extern-address space', <ExternObject Object cle##externs, maps [0x900000:0x97ffff]>), ('cle##tls', <ELFTLSObjectV2 Object cle##tls, maps [0xa00000:0xa1500f]>)])
  >>> loader.min_addr
  0x400000
  >>> loader.max_addr
  0xb07fff
  ```
  
- `factory`

  ```python
  
  ```


使用 `proj.factory.simulation_manager`可以模拟执行

------

## [Angr_CTF](https://github.com/jakespringer/angr_ctf)

先下载`angr_ctf`存储库。

```bash
git clone https://github.com/jakespringer/angr_ctf.git
```

可以输入`tree`查看库的层次结构，`dist`目录下存放着二进制文件和挖了空的`python`文件，在学习`angr`的过程中，只需要把空补齐即可。`solutions`存放着题解。

```bash
├── 00_angr_find
│   ├── 00_angr_find.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold00.py
├── 01_angr_avoid
│   ├── 01_angr_avoid.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold01.py
├── 02_angr_find_condition
│   ├── 02_angr_find_condition.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold02.py
├── 03_angr_symbolic_registers
│   ├── 03_angr_symbolic_registers.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold03.py
├── 04_angr_symbolic_stack
│   ├── 04_angr_symbolic_stack.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold04.py
├── 05_angr_symbolic_memory
│   ├── 05_angr_symbolic_memory.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold05.py
├── 06_angr_symbolic_dynamic_memory
│   ├── 06_angr_symbolic_dynamic_memory.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold06.py
├── 07_angr_symbolic_file
│   ├── 07_angr_symbolic_file.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold07.py
├── 08_angr_constraints
│   ├── 08_angr_constraints.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold08.py
├── 09_angr_hooks
│   ├── 09_angr_hooks.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold09.py
├── 10_angr_simprocedures
│   ├── 10_angr_simprocedures.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold10.py
├── 11_angr_sim_scanf
│   ├── 11_angr_sim_scanf.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold11.py
├── 12_angr_veritesting
│   ├── 12_angr_veritesting.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold12.py
├── 13_angr_static_binary
│   ├── 13_angr_static_binary.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold13.py
├── 14_angr_shared_library
│   ├── 14_angr_shared_library.c.templite
│   ├── 14_angr_shared_library_so.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold14.py
├── 15_angr_arbitrary_read
│   ├── 15_angr_arbitrary_read.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold15.py
├── 16_angr_arbitrary_write
│   ├── 16_angr_arbitrary_write.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold16.py
├── 17_angr_arbitrary_jump
│   ├── 17_angr_arbitrary_jump.c.templite
│   ├── description.txt
│   ├── generate.py
│   ├── __init__.py
│   └── scaffold17.py
├── dist
│   ├── 00_angr_find
│   ├── 01_angr_avoid
│   ├── 02_angr_find_condition
│   ├── 03_angr_symbolic_registers
│   ├── 04_angr_symbolic_stack
│   ├── 05_angr_symbolic_memory
│   ├── 06_angr_symbolic_dynamic_memory
│   ├── 07_angr_symbolic_file
│   ├── 08_angr_constraints
│   ├── 09_angr_hooks
│   ├── 10_angr_simprocedures
│   ├── 11_angr_sim_scanf
│   ├── 12_angr_veritesting
│   ├── 13_angr_static_binary
│   ├── 14_angr_shared_library
│   ├── 15_angr_arbitrary_read
│   ├── 16_angr_arbitrary_write
│   ├── 17_angr_arbitrary_jump
│   ├── lib14_angr_shared_library.so
│   ├── scaffold00.py
│   ├── scaffold01.py
│   ├── scaffold02.py
│   ├── scaffold03.py
│   ├── scaffold04.py
│   ├── scaffold05.py
│   ├── scaffold06.py
│   ├── scaffold07.py
│   ├── scaffold08.py
│   ├── scaffold09.py
│   ├── scaffold10.py
│   ├── scaffold11.py
│   ├── scaffold12.py
│   ├── scaffold13.py
│   ├── scaffold14.py
│   ├── scaffold15.py
│   ├── scaffold16.py
│   └── scaffold17.py
├── LICENSE
├── NOTES
├── package.py
├── README
├── requirements.txt
├── solutions
│   ├── 00_angr_find
│   │   ├── 00_angr_find
│   │   ├── scaffold00.py
│   │   └── solve00.py
│   ├── 01_angr_avoid
│   │   ├── 01_angr_avoid
│   │   ├── scaffold01.py
│   │   └── solve01.py
│   ├── 02_angr_find_condition
│   │   ├── 02_angr_find_condition
│   │   ├── scaffold02.py
│   │   └── solve02.py
│   ├── 03_angr_symbolic_registers
│   │   ├── 03_angr_symbolic_registers
│   │   ├── scaffold03.py
│   │   └── solve03.py
│   ├── 04_angr_symbolic_stack
│   │   ├── 04_angr_symbolic_stack
│   │   ├── scaffold04.py
│   │   └── solve04.py
│   ├── 05_angr_symbolic_memory
│   │   ├── 05_angr_symbolic_memory
│   │   ├── scaffold05.py
│   │   └── solve05.py
│   ├── 06_angr_symbolic_dynamic_memory
│   │   ├── 06_angr_symbolic_dynamic_memory
│   │   ├── scaffold06.py
│   │   └── solve06.py
│   ├── 07_angr_symbolic_file
│   │   ├── 07_angr_symbolic_file
│   │   ├── scaffold07.py
│   │   └── solve07.py
│   ├── 08_angr_constraints
│   │   ├── 08_angr_constraints
│   │   ├── scaffold08.py
│   │   └── solve08.py
│   ├── 09_angr_hooks
│   │   ├── 09_angr_hooks
│   │   ├── scaffold09.py
│   │   └── solve09.py
│   ├── 10_angr_simprocedures
│   │   ├── 10_angr_simprocedures
│   │   ├── scaffold10.py
│   │   └── solve10.py
│   ├── 11_angr_sim_scanf
│   │   ├── 11_angr_sim_scanf
│   │   ├── scaffold11.py
│   │   └── solve11.py
│   ├── 12_angr_veritesting
│   │   ├── 12_angr_veritesting
│   │   ├── scaffold12.py
│   │   └── solve12.py
│   ├── 13_angr_static_binary
│   │   ├── 13_angr_static_binary
│   │   ├── scaffold13.py
│   │   └── solve13.py
│   ├── 14_angr_shared_library
│   │   ├── 14_angr_shared_library
│   │   ├── lib14_angr_shared_library.so
│   │   ├── scaffold14.py
│   │   └── solve14.py
│   ├── 15_angr_arbitrary_read
│   │   ├── 15_angr_arbitrary_read
│   │   ├── scaffold15.py
│   │   └── solve15.py
│   ├── 16_angr_arbitrary_write
│   │   ├── 16_angr_arbitrary_write
│   │   ├── scaffold16.py
│   │   └── solve16.py
│   ├── 17_angr_arbitrary_jump
│   │   ├── 17_angr_arbitrary_jump
│   │   ├── scaffold17.py
│   │   └── solve17.py
│   └── run-all.sh
├── solve.py
├── SymbolicExecution.pptx
└── xx_angr_segfault
    ├── a
    ├── description.txt
    ├── generate.py
    ├── __init__.py
    ├── scaffoldxx.py
    └── xx_angr_segfault.c.templite

39 directories, 197 files
```

------

### 00_angr_find

先`file ./00_angr_find`查看文件类型。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/reverse/angr_ctf/]
└─$ file ./00_angr_find
./00_angr_find: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=83edb9b0f7da06e0355b5310294ae256ded72ca1, not stripped
```

用`IDA Pro 32bit`打开二进制文件`00_angr_find`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int i; // [esp+1Ch] [ebp-1Ch]
  char s1[9]; // [esp+23h] [ebp-15h]
  unsigned int v6; // [esp+2Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  printf("Enter the password: ");
  __isoc99_scanf("%8s", s1);
  for ( i = 0; i <= 7; ++i )
    s1[i] = complex_function(s1[i], i);
  if ( !strcmp(s1, "JACEJGCS") )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

可以看到`complex_function()`函数对用户输入的字符串进行处理后，与字符串`"JACEJGCS"`进行比较，若相等则输出`"Good Job."`。其中`puts("Good Job.");`的地址为`0x8048678`，编写`Python`代码用`angr`进行求解可以得到正确输入为`"JXWVXRKX"`。

```python
import angr

project = angr.Project('./00_angr_find')
initial_state = project.factory.entry_state()
simgr = project.factory.simgr(initial_state)
simgr.explore(find=0x8048678)
if simgr.found:
    solution_state = simgr.found[0]
    print(solution_state.posix.dumps(0))
else:
    raise Exception('Could not find the solution')
```

------

### 01_angr_avoid

先`file ./01_angr_find`查看文件类型。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/reverse/angr_ctf/]
└─$ file ./01_angr_find
./01_angr_avoid: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b2a7c5e56cec829714441aee4b163c411ae24e3d, not stripped
```

用`IDA Pro 32bit`打开二进制文件`01_angr_avoid`，按`F5`反汇编主函数源码，发现`IDA Pro`报错`too big function`，打开`IDA Pro`根目录的`ctg`目录下的`hexrays.cfg`，将`64`修改为`1024`即可。

```
MAX_FUNCSIZE            = 1024        // Functions over 1024K are not decompiled
```

其实直接看汇编代码也行，我们需要找到`"Good Job."`，其下面那行调用函数地址为`0x080485e5`，而`avoid_me`函数的地址为`0x080485A8`，编写`Python`代码用`angr`进行求解可以得到正确输入为`"HUJOZMYS"`。

```python
import angr

project = angr.Project('./01_angr_avoid')
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)
simulation.explore(find=0x80485e5, avoid=0x80485a8)
if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(0))
else:
    raise Exception('Could not find the solution')
```

------

### 02_angr_find_condition

先`file ./02_angr_find_condition`查看文件类型。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/reverse/angr_ctf/]
└─$ file ./02_angr_find_condition
02_angr_find_condition: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8f449fc89161a9f0a1b895fb352b85894ae7117f, not stripped
```

用`IDA Pro 32bit`打开二进制文件`02_angr_find_condition`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+18h] [ebp-40h]
  int j; // [esp+1Ch] [ebp-3Ch]
  char s1[20]; // [esp+24h] [ebp-34h] BYREF
  char s2[20]; // [esp+38h] [ebp-20h] BYREF
  unsigned int v8; // [esp+4Ch] [ebp-Ch]

  v8 = __readgsdword(0x14u);
  for ( i = 0; i <= 19; ++i )
    s2[i] = 0;
  qmemcpy(s2, "VXRRJEUR", 8);
  printf("Enter the password: ");
  __isoc99_scanf("%8s", s1);
  for ( j = 0; j <= 7; ++j )
    s1[j] = complex_function(s1[j], j + 8);
  if ( !strcmp(s1, s2) )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

`explore`的`find`和`avoid`可以传递函数作为参数，根据函数返回值来搜索过滤，判断当前符号执行的状态是否成功，编写`Python`代码用`angr`进行求解可以得到正确输入为`"HETOBRCU"`。

```python
import angr

project = angr.Project('./02_angr_find_condition')
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)

# set expected function to judge whether the output is succeessful according to the state.
# state.posix is the api for posix, and dumps(file discription number) will get the bytes for the pointed file. sys.stdout.fileno() is the stdout file discription number. we can replace it by 1.
def is_successful(state):
    return b'Good Job' in state.posix.dumps(1)

# set unexpected function
def should_abort(state):
    return b'Try again' in state.posix.dumps(1)

simulation.explore(find=is_successful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(0)) # 0 == sys.stdin.fileno()
else:
    raise Exception('Could not find the solution')
```

------

### 03_angr_simbolic_registers

先`file ./03_angr_symbolic_registers`查看文件类型。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/reverse/angr_ctf/]
└─$ file ./03_angr_symbolic_registers
03_angr_symbolic_registers: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=c0059af3c6c186fb950c307552251aadc0648fb0, not stripped
```

用`IDA Pro 32bit`打开二进制文件`03_angr_symbolic_registers`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  int v5; // [esp+4h] [ebp-14h]
  int v6; // [esp+8h] [ebp-10h]
  int v7; // [esp+Ch] [ebp-Ch]
  int v8; // [esp+Ch] [ebp-Ch]

  printf("Enter the password: ");
  v3 = get_user_input();
  v7 = HIDWORD(v3);
  v5 = complex_function_1(v3);
  v6 = complex_function_2();
  v8 = complex_function_3(v7);
  if ( v5 || v6 || v8 )
    puts("Try again.");
  else
    puts("Good Job.");
  return 0;
}
```

相应的汇编代码为：

```assembly
.text:0804895A                 lea     ecx, [esp+4]
.text:0804895E                 and     esp, 0FFFFFFF0h
.text:08048961                 push    dword ptr [ecx-4]
.text:08048964                 push    ebp
.text:08048965                 mov     ebp, esp
.text:08048967                 push    ecx
.text:08048968                 sub     esp, 14h
.text:0804896B                 sub     esp, 0Ch
.text:0804896E                 push    offset aEnterThePasswo ; "Enter the password: "
.text:08048973                 call    _printf
.text:08048978                 add     esp, 10h
.text:0804897B                 call    get_user_input
.text:08048980                 mov     [ebp+var_14], eax
.text:08048983                 mov     [ebp+var_10], ebx
.text:08048986                 mov     [ebp+var_C], edx
.text:08048989                 sub     esp, 0Ch
.text:0804898C                 push    [ebp+var_14]
.text:0804898F                 call    complex_function_1
.text:08048994                 add     esp, 10h
.text:08048997                 mov     ecx, eax
.text:08048999                 mov     [ebp+var_14], ecx
.text:0804899C                 sub     esp, 0Ch
.text:0804899F                 push    [ebp+var_10]
.text:080489A2                 call    complex_function_2
.text:080489A7                 add     esp, 10h
.text:080489AA                 mov     ecx, eax
.text:080489AC                 mov     [ebp+var_10], ecx
.text:080489AF                 sub     esp, 0Ch
.text:080489B2                 push    [ebp+var_C]
.text:080489B5                 call    complex_function_3
.text:080489BA                 add     esp, 10h
.text:080489BD                 mov     ecx, eax
.text:080489BF                 mov     [ebp+var_C], ecx
.text:080489C2                 cmp     [ebp+var_14], 0
.text:080489C6                 jnz     short loc_80489D4
.text:080489C8                 cmp     [ebp+var_10], 0
.text:080489CC                 jnz     short loc_80489D4
.text:080489CE                 cmp     [ebp+var_C], 0
.text:080489D2                 jz      short loc_80489E6
```

我们把`angr`执行的起始地址设置为`0x8048980`，用户输入的三个参数分别存入了`eax`，`ebx`，`edx`这三个寄存器。创建符号变量后，将这三个寄存器进行符号化处理，最后再对符号变量进行求解，得到`b9ffd04e ccf63fe8 8fd4d959`。

```python
import angr
import claripy

project = angr.Project('./03_angr_symbolic_registers')
start_address = 0x8048980
initial_state = project.factory.entry_state(addr=start_address)
# create some bitvector symbols to assign the registers.
password0 = claripy.BVS('p0', 32)
initial_state.regs.eax = password0
password1 = claripy.BVS('p1', 32)
initial_state.regs.ebx = password1
password2 = claripy.BVS('p2', 32)
initial_state.regs.edx = password2

# set expected function to judge whether the output is succeessful according to the state.
def is_successful(state):
    return b'Good Job' in state.posix.dumps(1)

# set unexpected function
def should_abort(state):
    return b'Try again' in state.posix.dumps(1)

simulation = project.factory.simgr(initial_state)
simulation.explore(find=is_successful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd0 = solution_state.solver.eval(password0)
    passwd1 = solution_state.solver.eval(password1)
    passwd2 = solution_state.solver.eval(password2)
    print(' '.join(map('{:x}'.format, [passwd0, passwd1, passwd2])))
else:
    raise Exception('Could not find the solution')
```

------

## 刷CTF时遇到的可用Angr的逆向题

### [Baby_re1](https://ce.pwnthebox.com/challenges?type=2&id=100)

简单的异或和替换...这些都是有路径的

编写`Python`代码，运行得到`flag{R3_1n_cRypt0}`，提交即可。

```python
import angr

proj = angr.Project("./baby_reverse")

# puts("Correct!")
target_addr = 0x401358

state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=target_addr)
state = simgr.found[0]
print(state.posix.dumps(0)) # flag{R3_1n_cRypt0}
```

------

