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
c.NotebookApp.port = 8888                # 任意指定一个不冲突的端口
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
virtualenv angr && source ./angr/bin/activate && pip install angr -i https://pypi.tuna.tsinghua.edu.cn/simple 
```

此外，如果不使用`virtualenv`来创建虚拟环境的话，用`conda`也可以。

```bash
conda create -n angr
conda activate angr
pip install angr
```

`angr`官方推荐使用虚拟环境运行，每次需要调用具有`angr`环境时，只需要执行：

```shell
virtualenv --python=$(which python3) angr
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

### 使用方法 

官方的API文档：[**angr API documentation**](https://api.angr.io)。`Angr`还有一个GUI版本可用：[**angr Management**](https://github.com/angr/angr-management)。

`angr` 的使用步骤大致如下：

- 创建 `Project` 对象，`Project` 会解析二进制文件的结构，包括内存布局、符号表、重定位表等，以便进行静态和动态分析。

    ```python
    >>> import angr
    >>> proj = angr.Project('./00_angr_find')
    ```

- `Project` 有一些基础属性。

    ```python
    >>> proj.filename  # 二进制文件名
    './00_angr_find'
    >>> proj.arch      # 二进制文件的体系结构
    <Arch X86 (LE)>
    >>> proj.entry     # 二进制文件的入口地址
    134513744
    >>> hex(proj.entry) 
    '0x8048450'
    >>> import monkeyhex
    >>> proj.entry
    >>> 0x8048450
    >>> proj.loader   # 二进制文件的加载器, 用于解析二进制文件的结构, 程序加载时会将二进制文件和共享库映射到虚拟地址中, CLE模块就是用来处理这些的
    <Loaded 00_angr_find, maps [0x8048000:0x8707fff]>
    ```

- `arch`也有一些基础属性。

    ```python
    >>> arch = proj.arch  # 二进制文件的架构
    >>> arch
    <Arch X86 (LE)>
    >>> arch.name
    'X86'
    >>> arch.bits
    0x20
    >>> arch.bytes
    0x4
    >>> arch.vex_arch
    'VexArchX86'
    >>> arch.qemu_name
    'i386'
    >>> arch.ida_processor
    'metapc'
    >>> arch.triplet
    'i386-linux-gnu'
    >>> arch.max_inst_bytes
    0xf
    >>> arch.ip_offset
    0x44
    >>> arch.sp_offset
    0x18
    >>> arch.bp_offset
    0x1c
    >>> arch.lr_offset
    >>> arch.vex_conditional_helpers
    True
    >>> arch.syscall_num_offset
    0x8
    >>> arch.call_pushes_ret
    True
    >>> arch.stack_change
    -0x4
    >>> arch.memory_endness
    'Iend_LE'
    >>> arch.register_endness
    'Iend_LE'
    >>> arch.instruction_endness
    'Iend_BE'
    >>> arch.sizeof
    {'short': 0x10, 'int': 0x20, 'long': 0x40, 'long long': 0x40}
    ```

- 二进制文件的加载器 `loader` 用于解析二进制文件的结构，程序加载时会将二进制文件和共享库映射到虚拟地址中，`CLE`模块就是用来处理这些的。
  
  ```python
  >>> loader = proj.loader
  >>> loader
  <Loaded baby_reverse, maps [0x400000:0xb07fff]>
  >>> loader.main_object  # Project加载的二进制文件信息 名字 映射地址
  <ELF Object 00_angr_find, maps [0x8048000:0x804a03f]>
  >>> loader.main_object.pic  # 查询主对象是否开启了PIC, 即查询二进制程序是否开启地址随机化
  False
  >>> loader.main_object.execstack  # 查询主对象是否开启了NX 栈是否可执行, 即查询二进制文件是否拥有可执行栈
  False
  >>> loader.shared_objects  # 与二进制文件共同加载的共享库信息, 共享目标文件的信息 名字 映射地址 
  {'00_angr_find': <ELF Object 00_angr_find, maps [0x8048000:0x804a03f]>,
   'libc.so.6': <ELF Object libc.so.6, maps [0x8100000:0x832791b]>,
   'ld-linux.so.2': <ELF Object ld-linux.so.2, maps [0x8400000:0x8434a3f]>,
   'extern-address space': <ExternObject Object cle##externs, maps [0x8500000:0x8507fff]>,
   'cle##tls': <ELFTLSObjectV2 Object cle##tls, maps [0x8600000:0x8614807]>}
  >>> loader.all_elf_objects   # 所有ELF对象文件
  [<ELF Object 00_angr_find, maps [0x8048000:0x804a03f]>,
   <ELF Object libc.so.6, maps [0x8100000:0x832791b]>,
   <ELF Object ld-linux.so.2, maps [0x8400000:0x8434a3f]>]
  >>> loader.extern_object  # 外部对象文件
  <ExternObject Object cle##externs, maps [0x8500000:0x8507fff]>
  >>> loader.kernel_object  # 内核对象文件
  <KernelObject Object cle##kernel, maps [0x8700000:0x8707fff]>
  >>> loader.main_object.plt
  {'strcmp': 0x80483d0,
   'printf': 0x80483e0,
   '__stack_chk_fail': 0x80483f0,
   'puts': 0x8048400,
   'exit': 0x8048410,
   '__libc_start_main': 0x8048420,
   '__isoc99_scanf': 0x8048430,
   '__gmon_start__': 0x8048440}
  >>> loader.main_object.imports['__libc_start_main']
  <cle.backends.elf.relocation.i386.R_386_JMP_SLOT object at 0x7f0f4739c750>
  >>> loader.main_object.segments
  <Regions: [<ELFSegment flags=0x5, relro=0x0, vaddr=0x8048000, memsize=0x8b4, filesize=0x8b4, offset=0x0>, <ELFSegment flags=0x4, relro=0x1, vaddr=0x8049f08, memsize=0xf8, filesize=0xf8, offset=0xf08>, <ELFSegment flags=0x6, relro=0x0, vaddr=0x804a000, memsize=0x40, filesize=0x3d, offset=0x1000>]>
  >>> loader.min_addr
  0x8048000
  >>> loader.max_addr
  0x8707fff
  >>> printf = loader.find_symbol('printf')
  >>> printf
  <Symbol "printf" in libc.so.6 at 0x8153e40>
  >>> printf.name   # 符号名称 
  'printf'
  >>> printf.owner  # 拥有该符号的ELF对象
  <ELF Object libc.so.6, maps [0x8100000:0x832791b]>
  >>> printf.rebased_addr  # 将库加载到进程的地址空间后, 内存中符号的绝对地址
  0x8153e40
  >>> printf.linked_addr   # 库文件中该符号的地址
  0x53e40
  >>> printf.relative_addr  # 相对于库文件基地址的该符号地址
  0x53e40
  >>> printf.is_import  # 该符号是否为导入的符号, 即它是否在另一个库中定义而在该库中使用的符号
  False
  >>> printf.is_export  # 该符号是否为导出的符号, 即它在此库中定义并且能提供给其他库或程序使用
  True
  ```
  
- 通过`factory`提供的构造函数可以方便地创建对象。

  ```python
  >>> factory = proj.factory
  >>> factory
  <angr.factory.AngrObjectFactory object at 0x7f0f46644c10>
  >>> block = factory.block(proj.entry)  # 创建一个起始地址为二进制文件入口点地址的基本代码块对象
  >>> block
  <Block for 0x8048450, 33 bytes>
  >>> block.pp()   # 基本代码块的汇编指令代码 pp为pretty print的缩写
           _start:
  8048450  xor     ebp, ebp
  8048452  pop     esi
  8048453  mov     ecx, esp
  8048455  and     esp, 0xfffffff0
  8048458  push    eax
  8048459  push    esp
  804845a  push    edx
  804845b  push    __libc_csu_fini
  8048460  push    __libc_csu_init
  8048465  push    ecx
  8048466  push    esi
  8048467  push    main
  804846c  call    __libc_start_main
  >>> block.instructions  # 基本代码块的汇编指令数目
  0xd
  >>> block.instruction_addrs  # 基本代码块的每条汇编指令的起始地址
  (0x8048450,
   0x8048452,
   0x8048453,
   0x8048455,
   0x8048458,
   0x8048459,
   0x804845a,
   0x804845b,
   0x8048460,
   0x8048465,
   0x8048466,
   0x8048467,
   0x804846c)
  ```

`project`对象只能表示程序的初始镜像。在用`angr`执行程序时，需要用`SimState`对象来表示模拟的程序状态，`SimState`对象包含任何能够在运行过程中被改变的实时数据，如内存、寄存器、文件系统数据...... 

注意`i386`和`amd64`的寄存器是不同的，所以`32`位和`64`位的二进制程序的`.regs`属性下的子属性也不一样。

```python
>>> state = factory.entry_state()
>>> state
<SimState @ 0x8048450>
# 访问寄存器值
>>> state.regs  
<angr.state_plugins.view.SimRegNameView object at 0x7f0f45fd4550>
>>> state.regs.eax
<BV32 0x1c>
>>> state.regs.eip
<BV32 0x8048450>
>>> addr = state.regs.esp
>>> addr
<BV32 0x7ffeffac>
>>> state.mem[addr].int.resolved  # 访问内存值(以C语言中的int型)
<BV32 0x1>
>>> state.mem[addr].double = 5.2  # 设置内存值(以C语言的double类型)
>>> state.mem[addr].double.resolved
<FP64 FPV(5.2, DOUBLE)>
>>> state.regs.esi = state.solver.BVV(6, 64)  # 设置寄存器值
>>> state.regs.esi
<BV32 0x6>
```

`python`中的整数型和`bitvector`类型的相互转化如下：

```python
>>> bv = state.solver.BVV(0x1234, 32)  # int转bitvector
>>> pi = state.solver.eval(bv)         # bitvector转int
>>> bv
<BV32 0x1234>
>>> pi
0x1234
```

通过`proj.factory.simulation_manager`或者`proj.factory.simgr`创建模拟管理器，我们可以模拟执行二进制文件。

```python
>>> simgr = proj.factory.simgr(state)
>>> simgr
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x8048450>]
>>> simgr.explore(find=0x8048678)
<SimulationManager with 1 active, 16 deadended, 1 found>
>>> simgr.found
[<SimState @ 0x8048678>]
>>> simgr.found[0].posix.dumps(0)
b'JXWVXRKX'
>>> simgr.active[0].regs.eip  # 查看模拟执行后当前state的eip
<BV32 0x8048670>
>>> state.regs.eip  # 原始state的eip并没变
<BV32 0x8048450>
```

此外，`angr`在`Project.analyses.`中提供了大量函数用于程序分析。

```python
>>> cfg = proj.analyses.CFGFast()  # 控制流分析图
>>> cfg
<CFGFast Analysis Result at 0x7fcd8b69b150>
>>> cfg.graph
<networkx.classes.digraph.DiGraph object at 0x7fcd82c2a210>  # 详情请查看networkx
>>> len(cfg.graph.nodes())  # 返回图中节点的数量
0x1ca61
>>> entry_node = cfg.get_any_node(proj.entry)  # 获取程序入口地址处的节点
>>> entry_node
<CFGNode _start [33]>
>>> len(list(cfg.graph.successors(entry_node)))  # 计算指定节点的后继节点数量
0x1
# 可以安装scipy和matplotlib模块画图
>>> import networkx as nx
>>> import matplotlib
>>> matplotlib.use('Agg')
>>> import matplotlib.pyplot as plt
>>> nx.draw(cfg.graph)
>>> plt.savefig('tmp.png')
```

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

先用`file ./00_angr_find`查看文件类型，并用`checksec ./00_angr_find`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./00_angr_find
./00_angr_find: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=83edb9b0f7da06e0355b5310294ae256ded72ca1, not stripped

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./00_angr_find         
[*] '/home/tyd/ctf/Angr_CTF/00_angr_find'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
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

可以看到`complex_function()`函数对用户输入的字符串进行处理后，与字符串`"JACEJGCS"`进行比较，若相等则输出`"Good Job."`。双击查看`complex_function()`函数：

```c
int __cdecl complex_function(int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (3 * a2 + a1 - 65) % 26 + 65;
}
```

其中`puts("Good Job.");`的`"Good Job"`地址为`0x8048678`，相应的汇编代码如下：

```assembly
.text:08048675 loc_8048675:                            ; CODE XREF: main+9A↑j
.text:08048675                 sub     esp, 0Ch
.text:08048678                 push    offset aGoodJob ; "Good Job."
.text:0804867D                 call    _puts
.text:08048682                 add     esp, 10h
```

编写`Python`代码用`angr`进行求解可以得到正确输入为`"JXWVXRKX"`。

```python
import angr

project = angr.Project('./00_angr_find')
initial_state = project.factory.entry_state(add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
simulation = project.factory.simgr(initial_state)
simulation.explore(find=0x8048678)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()
    print('[+] Congratulations! Solution is: %s' % passwd)
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 00_angr_find.py 
[+] Congratulations! Solution is: JXWVXRKX

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./00_angr_find 
Enter the password: JXWVXRKX
Good Job.
```

这道基础题主要是让我们熟悉`Angr`的基本使用流程，一般步骤如下：

- 创建`project`加载二进制文件。
- 设置程序入口`state`，`add_options`参数用于添加选项，这里设置了符号执行过程中对未约束的内存和寄存器进行填充。
- 创建`simgr`将初始状态加载到模拟器中。
- 使用`simgr.explore()`函数运行分析。
- 通过`simgr.found`属性获取符号执行的路径，解析执行结果。

------

### 01_angr_avoid

先用`file ./01_angr_avoid`查看文件类型，并用`checksec ./01_angr_avoid`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./01_angr_avoid
./01_angr_avoid: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b2a7c5e56cec829714441aee4b163c411ae24e3d, not stripped

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./01_angr_avoid
[*] '/home/tyd/ctf/Angr_CTF/01_angr_avoid'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`01_angr_avoid`，按`F5`反汇编主函数源码，发现`IDA Pro`报错`too big function`，打开`IDA Pro`根目录的`ctg`目录下的`hexrays.cfg`，将`64`修改为`1024`即可，然而发现再次按`F5`依旧很慢，可以选择用 [**retdec**](https://github.com/avast/retdec) 来查看反汇编源码。

```
MAX_FUNCSIZE            = 1024        // Functions over 1024K are not decompiled
```

其实直接看汇编代码也行，我们需要找到`"Good Job."`，其下面那行调用函数地址为`0x080485e5`。

```assembly
.text:080485E0                 push    offset aGoodJob ; "Good Job."
.text:080485E5                 call    _puts
```

而`avoid_me`函数的起始地址为`0x080485A8`。

```assembly
.text:080485A8                 public avoid_me
.text:080485A8 avoid_me        proc near               ; CODE XREF: main+1CA↓p
.text:080485A8                                         ; main+1FB↓p ...
.text:080485A8 ; __unwind {
.text:080485A8                 push    ebp
.text:080485A9                 mov     ebp, esp
.text:080485AB                 mov     should_succeed, 0
.text:080485B2                 nop
.text:080485B3                 pop     ebp
.text:080485B4                 retn
.text:080485B4 ; } // starts at 80485A8
.text:080485B4 avoid_me        endp
```

编写`Python`代码用`angr`进行求解可以得到正确输入为`"HUJOZMYS"`。

```python
import angr

project = angr.Project('./01_angr_avoid')
initial_state = project.factory.entry_state(add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
simulation = project.factory.simgr(initial_state)
simulation.explore(find=0x80485e5, avoid=0x80485a8)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()
    print('[+] Congratulations! Solution is: %s' % passwd)
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 01_angr_avoid.py
[+] Congratulations! Solution is: HUJOZMYS

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./01_angr_avoid         
Enter the password: HUJOZMYS
Good Job.
```

------

### 02_angr_find_condition

先用`file ./02_angr_find_condition`查看文件类型，并用`checksec ./02_angr_find_condition`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./02_angr_find_condition
02_angr_find_condition: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8f449fc89161a9f0a1b895fb352b85894ae7117f, not stripped

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./02_angr_find_condition    
[*] '/home/tyd/ctf/Angr_CTF/02_angr_find_condition'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
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
initial_state = project.factory.entry_state(add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
simulation = project.factory.simgr(initial_state)
# set expected function to judge whether the output is succeessful according to the state.
# state.posix is the api for posix, and dumps(file discription number) will get the bytes for the pointed file. sys.stdout.fileno() is the stdout file discription number. we can replace it by 1.
# set expected function to judge whether the output is succeessful according to the state.
def is_successful(state):
    return b'Good Job' in state.posix.dumps(1)
# is_successful = lambda state: b'Good Job' in state.posix.dumps(1)
# set unexpected function
def should_abort(state):
    return b'Try again' in state.posix.dumps(1)
# should_abort = lambda state: b'Try again' in state.posix.dumps(1)

simulation.explore(find=is_successful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()   # 0 == sys.stdin.fileno()
    print('[+] Congratulations! Solution is: %s' % passwd)
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 02_angr_find_condition.py
[+] Congratulations! Solution is: HETOBRCU

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./02_angr_find_condition    
Enter the password: HETOBRCU
Good Job.
```

------

### 03_angr_simbolic_registers

先用`file ./03_angr_symbolic_registers`查看文件类型，并用`checksec ./03_angr_symbolic_registers`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./03_angr_symbolic_registers
03_angr_symbolic_registers: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=c0059af3c6c186fb950c307552251aadc0648fb0, not stripped

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./03_angr_symbolic_registers
[*] '/home/tyd/ctf/Angr_CTF/03_angr_symbolic_registers'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
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

双击`get_user_input()`函数查看详情：

```assembly
int get_user_input()
{
  int v1; // [esp+0h] [ebp-18h] BYREF
  int v2; // [esp+4h] [ebp-14h] BYREF
  int v3[4]; // [esp+8h] [ebp-10h] BYREF

  v3[1] = __readgsdword(0x14u);
  __isoc99_scanf("%x %x %x", &v1, &v2, v3);
  return v1;
}
```

其中寄存器传参的关键汇编代码如下：

```assembly
.text:0804892A                 push    offset aXXX     ; "%x %x %x"
.text:0804892F                 call    ___isoc99_scanf
.text:08048934                 add     esp, 10h
.text:08048937                 mov     ecx, [ebp+var_18]
.text:0804893A                 mov     eax, ecx
.text:0804893C                 mov     ecx, [ebp+var_14]
.text:0804893F                 mov     ebx, ecx
.text:08048941                 mov     ecx, [ebp+var_10]
.text:08048944                 mov     edx, ecx
```

我们把`angr`执行的起始地址设置为`0x8048980`，用户输入的三个参数分别存入了`eax`，`ebx`，`edx`这三个寄存器。创建符号变量后，将这三个寄存器进行符号化处理，最后再对符号变量进行求解。编写`Python`代码求解得到`b9ffd04e ccf63fe8 8fd4d959`。

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
is_successful = lambda state: b'Good Job' in state.posix.dumps(1)
# set unexpected function
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation = project.factory.simgr(initial_state)
simulation.explore(find=is_successful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd0 = solution_state.solver.eval(password0)
    passwd1 = solution_state.solver.eval(password1)
    passwd2 = solution_state.solver.eval(password2)
    solution = ' '.join(map('{:x}'.format, [passwd0, passwd1, passwd2]))
    print('[+] Congratulations! Solution is:', solution)
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 03_angr_symbolic_registers.py
[+] Congratulations! Solution is: b9ffd04e ccf63fe8 8fd4d959

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./03_angr_symbolic_registers
Enter the password: b9ffd04e ccf63fe8 8fd4d959
Good Job.
```

------

### 04_angr_simbolic_stack

先用`file ./04_angr_simbolic_stack`查看文件类型，并用`checksec ./04_angr_simbolic_stack`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./04_angr_symbolic_stack
./04_angr_symbolic_stack: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=cc18a41b58d7abfa868efc3be085b5712c6ea5ff, not stripped

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./04_angr_symbolic_stack         
[*] '/home/tyd/ctf/Angr_CTF/04_angr_symbolic_stack'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`04_angr_simbolic_stack`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  printf("Enter the password: ");
  handle_user();
  return 0;
}
```

双击`handle_user()`函数查看详情。

```c
int handle_user()
{
  int result; // eax
  int v1; // [esp+8h] [ebp-10h] BYREF
  int v2[3]; // [esp+Ch] [ebp-Ch] BYREF

  __isoc99_scanf("%u %u", v2, &v1);
  v2[0] = complex_function0(v2[0]);
  v1 = complex_function1(v1);
  if ( v2[0] == 1999643857 && v1 == -1136455217 )
    result = puts("Good Job.");
  else
    result = puts("Try again.");
  return result;
}
```

其中，`complex_function0()`函数如下：

```c
int __cdecl complex_function0(int a1)
{
  return a1 ^ 0x12A567E5;
}
```

`complex_function1()`函数如下：

```c
int __cdecl complex_function1(int a1)
{
  return a1 ^ 0x31BCB5D0;
}
```

其中`handle_user()`函数相应的汇编代码如下：

```assembly
.text:08048679                 public handle_user
.text:08048679 handle_user     proc near               ; CODE XREF: main+21↓p
.text:08048679
.text:08048679 var_10          = dword ptr -10h
.text:08048679 var_C           = dword ptr -0Ch
.text:08048679
.text:08048679 ; __unwind {
.text:08048679                 push    ebp
.text:0804867A                 mov     ebp, esp
.text:0804867C                 sub     esp, 18h
.text:0804867F                 sub     esp, 4
.text:08048682                 lea     eax, [ebp+var_10]
.text:08048685                 push    eax
.text:08048686                 lea     eax, [ebp+var_C]
.text:08048689                 push    eax
.text:0804868A                 push    offset aUU      ; "%u %u"
.text:0804868F                 call    ___isoc99_scanf
.text:08048694                 add     esp, 10h
.text:08048697                 mov     eax, [ebp+var_C]   ; 参数1 [ebp-0Ch]
.text:0804869A                 sub     esp, 0Ch
.text:0804869D                 push    eax
.text:0804869E                 call    complex_function0
.text:080486A3                 add     esp, 10h
.text:080486A6                 mov     [ebp+var_C], eax
.text:080486A9                 mov     eax, [ebp+var_10]  ; 参数2 [ebp-10h]
.text:080486AC                 sub     esp, 0Ch
.text:080486AF                 push    eax
.text:080486B0                 call    complex_function1
.text:080486B5                 add     esp, 10h
.text:080486B8                 mov     [ebp+var_10], eax
.text:080486BB                 mov     eax, [ebp+var_C]
.text:080486BE                 cmp     eax, 773024D1h
.text:080486C3                 jnz     short loc_80486CF
.text:080486C5                 mov     eax, [ebp+var_10]
.text:080486C8                 cmp     eax, 0BC4311CFh
.text:080486CD                 jz      short loc_80486E1
.text:080486CF
.text:080486CF loc_80486CF:                            ; CODE XREF: handle_user+4A↑j
.text:080486CF                 sub     esp, 0Ch
.text:080486D2                 push    offset s        ; "Try again."
.text:080486D7                 call    _puts
.text:080486DC                 add     esp, 10h
.text:080486DF                 jmp     short loc_80486F1
.text:080486E1 ; ---------------------------------------------------------------------------
.text:080486E1
.text:080486E1 loc_80486E1:                            ; CODE XREF: handle_user+54↑j
.text:080486E1                 sub     esp, 0Ch
.text:080486E4                 push    offset aGoodJob ; "Good Job."
.text:080486E9                 call    _puts
.text:080486EE                 add     esp, 10h
.text:080486F1
.text:080486F1 loc_80486F1:                            ; CODE XREF: handle_user+66↑j
.text:080486F1                 nop
.text:080486F2                 leave
.text:080486F3                 retn
.text:080486F3 ; } // starts at 8048679
.text:080486F3 handle_user     endp
```

上题是用寄存器传参，而这题变成用栈空间传参，我们需要学习怎么对栈空间中的值进行符号化处理。参数在栈上的分布情况大致如下：

- `password1`占用栈地址：`| 0x10 | 0x0F | 0x0E | 0x0D |`。
- `password2`占用栈地址：`| 0x0C | 0x0B | 0x0A | 0x09 |`。

```
  #            /-------- The stack --------\
  # [esp] ->   |                           |
  #                        . . .
  #            |---------------------------|
  # [ebp-0x10] |   password0, first byte   |
  #            |---------------------------|
  # [ebp-0x0F] |   password0, second byte  |
  #            |---------------------------|
  # [ebp-0x0E] |   password0, third byte   |
  #            |---------------------------|
  # [ebp-0x0D] |   password0, last byte    |  
  #            |---------------------------|
  # [ebp-0x0C] |   password1, first byte   |
  #            |---------------------------|
  # [ebp-0x0B] |   password1, second byte  |
  #            |---------------------------|
  # [ebp-0x0A] |   password1, third byte   |
  #            |---------------------------|
  # [ebp-0x09] |   password1, last byte    |
  #            |---------------------------|
  #                        . . .
  #            |---------------------------|
  #            |       more padding        |
  #            |---------------------------|
  #                        . . .
  #            |---------------------------|
  # [ebp] ->   |         padding           |
  #            \---------------------------/
```

编写`Python`代码求解得到俩个密码：`1704280884 2382341151`。

```python
import angr
import claripy

project = angr.Project('./04_angr_symbolic_stack')
start_address = 0x8048697
initial_state = project.factory.blank_state(addr=start_address)
initial_state.regs.ebp = initial_state.regs.esp
password0 = claripy.BVS('p0', 32)
password1 = claripy.BVS('p1', 32)
# simulate the stack
padding = 0x8
initial_state.regs.esp -= padding
initial_state.stack_push(password0)
initial_state.stack_push(password1)
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd0 = solution_state.solver.eval(password0)
    passwd1 = solution_state.solver.eval(password1)
    print('[+] Congratulations! Solution is: {} {}'.format(passwd0, passwd1))
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 04_angr_simbolic_stack.py 
[+] Congratulations! Solution is: 1704280884 2382341151

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./04_angr_symbolic_stack
Enter the password: 1704280884 2382341151
Good Job.
```

这里展开说下`solver`。

- `solver.eval(expression)` 将会解出一个可行解。
- `solver.eval_one(expression)`将会给出一个表达式的可行解，若有多个可行解，则抛出异常。
- `solver.eval_upto(expression, n)`将会给出最多n个可行解，如果不足n个就给出所有的可行解。
- `solver.eval_exact(expression, n)`将会给出n个可行解，如果解的个数不等于n个，将会抛出异常。
- `solver.min(expression)`将会给出最小可行解。
- `solver.max(expression)`将会给出最大可行解。

------

### 05_angr_symbolic_memory

先用`file ./05_angr_symbolic_memory`查看文件类型，并用`checksec ./05_angr_symbolic_memory`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./05_angr_symbolic_memory
./05_angr_symbolic_memory: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ca0d1114af914bf2d4c73a18488e43c670f6f617, not stripped

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./05_angr_symbolic_memory                                     
[*] '/home/tyd/ctf/Angr_CTF/05_angr_symbolic_memory'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`05_angr_symbolic_memory`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+Ch] [ebp-Ch]

  memset(user_input, 0, 0x21u);
  printf("Enter the password: ");
  __isoc99_scanf("%8s %8s %8s %8s", user_input, &unk_A1BA1C8, &unk_A1BA1D0, &unk_A1BA1D8);
  for ( i = 0; i <= 31; ++i )
    *(_BYTE *)(i + 169583040) = complex_function(*(char *)(i + 169583040), i);
  if ( !strncmp(user_input, "NJPURZPCDYEAXCSJZJMPSOMBFDDLHBVN", 0x20u) )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

双击`complex_function()`函数查看详情：

```c
int __cdecl complex_function(int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (9 * a2 + a1 - 65) % 26 + 65;
}
```

用户输入的那四个八字节长度的字符串是存放在`.bss`段上的，分别位于地址`[0xA1BA1C0, 0xA1BA1C8, 0xA1BA1D0, 0xA1BA1D8]`。

```assembly
.bss:0A1BA1C0 user_input      db 8 dup(?)             ; DATA XREF: main+18↑o
.bss:0A1BA1C8 unk_A1BA1C8     db    ? ;               ; DATA XREF: main+42↑o
.bss:0A1BA1D0 unk_A1BA1D0     db    ? ;               ; DATA XREF: main+3D↑o
.bss:0A1BA1D8 unk_A1BA1D8     db    ? ;               ; DATA XREF: main+38↑o
```

输入的字符串经过`complex_function()`函数进行变换后与字符串`"NJPURZPCDYEAXCSJZJMPSOMBFDDLHBVN"`比较`0x20`个字符。

```assembly
.text:080485E0                 push    offset unk_A1BA1D8
.text:080485E5                 push    offset unk_A1BA1D0
.text:080485EA                 push    offset unk_A1BA1C8
.text:080485EF                 push    offset user_input
.text:080485F4                 push    offset a8s8s8s8s ; "%8s %8s %8s %8s"
.text:080485F9                 call    ___isoc99_scanf
.text:080485FE                 add     esp, 20h
.text:08048601                 mov     [ebp+var_C], 0
.text:08048608                 jmp     short loc_8048637
```

编写`Python`代码求解得到`NAXTHGNR JVSFTPWE LMGAUHWC XMDCPALU`。

```python
import angr
import claripy

path_to_binary = './05_angr_symbolic_memory'
project = angr.Project(path_to_binary, auto_load_libs=False)
start_address = 0x8048601
initial_state = project.factory.blank_state(
    addr = start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)
# The binary is calling scanf("%8s %8s %8s %8s").
password0_address = 0xA1BA1C0
password0 = claripy.BVS('p0', 64)
initial_state.memory.store(password0_address, password0)
password1 = claripy.BVS('p1', 64)
initial_state.memory.store(password0_address+0x8, password1)
password2 = claripy.BVS('p2', 64)
initial_state.memory.store(password0_address+0x10, password2)
password3 = claripy.BVS('p3', 64)
initial_state.memory.store(password0_address+0x18, password3)
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd0 = solution_state.solver.eval(password0, cast_to=bytes).decode()
    passwd1 = solution_state.solver.eval(password1, cast_to=bytes).decode()
    passwd2 = solution_state.solver.eval(password2, cast_to=bytes).decode()
    passwd3 = solution_state.solver.eval(password3, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: {} {} {} {}'.format(passwd0, passwd1, passwd2, passwd3))
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 05_angr_symbolic_memory.py                                                      
[+] Congratulations! Solution is: NAXTHGNR JVSFTPWE LMGAUHWC XMDCPALU
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./05_angr_symbolic_memory
Enter the password: NAXTHGNR JVSFTPWE LMGAUHWC XMDCPALU
Good Job.
```

------

### 06_angr_symbolic_dynamic_memory

先用`file ./06_angr_symbolic_dynamic_memory`查看文件类型，并用`checksec ./06_angr_symbolic_dynamic_memory`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./06_angr_symbolic_dynamic_memory
./06_angr_symbolic_dynamic_memory: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a57d92f3fa4453d8d7655412932dc0f3dfa1fcf6, not stripped

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./06_angr_symbolic_dynamic_memory                                            
[*] '/home/tyd/ctf/Angr_CTF/06_angr_symbolic_dynamic_memory'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`06_angr_symbolic_dynamic_memory`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // ebx
  char *v4; // ebx
  int v6; // [esp-10h] [ebp-1Ch]
  int i; // [esp+0h] [ebp-Ch]

  buffer0 = (char *)malloc(9u);
  buffer1 = (char *)malloc(9u);
  memset(buffer0, 0, 9u);
  memset(buffer1, 0, 9u);
  printf("Enter the password: ");
  __isoc99_scanf("%8s %8s", buffer0, buffer1, v6);
  for ( i = 0; i <= 7; ++i )
  {
    v3 = &buffer0[i];
    *v3 = complex_function(buffer0[i], i);
    v4 = &buffer1[i];
    *v4 = complex_function(buffer1[i], i + 32);
  }
  if ( !strncmp(buffer0, "UODXLZBI", 8u) && !strncmp(buffer1, "UAORRAYF", 8u) )
    puts("Good Job.");
  else
    puts("Try again.");
  free(buffer0);
  free(buffer1);
  return 0;
}
```

双击`complex_function()`函数查看详情：

```c
int __cdecl complex_function(int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (13 * a2 + a1 - 65) % 26 + 65;
}
```

注意到程序使用`malloc()`函数分配了两个大小为`9`字节的缓冲区，并用 `memset()`函数将其初始化为`0`。`buffer0`和`buffer1`这俩个缓冲区都是在`.bss`段上的，用户的输入被作为格式化字符串存入这俩个缓冲区内。经过`complex_function()`函数的变换后的字符串分别与字符串`"UODXLZBI"`和`"UAORRAYF"`。

```assembly
.bss:0ABCC8A4 buffer0         dd ?                    ; DATA XREF: main+1F↑w
.bss:0ABCC8AC buffer1         dd ?                    ; DATA XREF: main+31↑w
```

我们可以选择地址`0x8048699`作为初始状态，这样可以跳过所有的`malloc()`函数。

```assembly
.text:0804868A                 push    edx
.text:0804868B                 push    eax
.text:0804868C                 push    offset a8s8s    ; "%8s %8s"
.text:08048691                 call    ___isoc99_scanf
.text:08048696                 add     esp, 10h
.text:08048699                 mov     [ebp+var_C], 0
.text:080486A0                 jmp     short loc_8048706
```

由于缓冲区的大小是`8`字节，我们初始化两个大小为`64`位的符号位向量。我们可以任选俩个堆地址放入缓冲区`buffer0`和`buffer1`中， `endness` 用于设置端序，`angr`默认为大端序`BE`，我们直接将其设置为与二进制文件的架构端序一致即可。编写`Python`代码求解得到`UBDKLMBV UNOERNYS`。

```python
import angr
import claripy

path_to_binary = './06_angr_symbolic_dynamic_memory'
project = angr.Project(path_to_binary, auto_load_libs=False)
start_address = 0x8048699
initial_state = project.factory.blank_state(
    addr = start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)
# The binary is calling scanf("%8s %8s").
password0 = claripy.BVS('p0', 64)
password1 = claripy.BVS('p1', 64)
fake_heap_address0 = 0xffff666
pointer_to_malloc_memory_address0 = 0xABCC8A4
initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
initial_state.memory.store(fake_heap_address0, password0)
fake_heap_address1 = 0xffff676
pointer_to_malloc_memory_address1 = 0xABCC8AC
initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)
initial_state.memory.store(fake_heap_address1, password1)
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd0 = solution_state.solver.eval(password0, cast_to=bytes).decode()
    passwd1 = solution_state.solver.eval(password1, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: {} {}'.format(passwd0, passwd1))
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 06_angr_symbolic_dynamic_memory.py
[+] Congratulations! Solution is: UBDKLMBV UNOERNYS

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./06_angr_symbolic_dynamic_memory     
Enter the password: UBDKLMBV UNOERNYS
Good Job.
```

------

### 07_angr_symbolic_file

先用`file ./07_angr_symbolic_file`查看文件类型，并用`checksec ./07_angr_symbolic_file`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./07_angr_symbolic_file          
./07_angr_symbolic_file: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d407b80daa3eac2fb804414a1ff45f3850bea38b, not stripped
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./07_angr_symbolic_file 
[*] '/home/tyd/ctf/Angr_CTF/07_angr_symbolic_file'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`07_angr_symbolic_file`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+Ch] [ebp-Ch]

  memset(buffer, 0, sizeof(buffer));
  printf("Enter the password: ");
  __isoc99_scanf("%64s", buffer);
  ignore_me((int)buffer, 0x40u);
  memset(buffer, 0, sizeof(buffer));
  fp = fopen("OJKSQYDP.txt", "rb");
  fread(buffer, 1u, 0x40u, fp);
  fclose(fp);
  unlink("OJKSQYDP.txt");
  for ( i = 0; i <= 7; ++i )
    *(_BYTE *)(i + 134520992) = complex_function(*(char *)(i + 134520992), i);
  if ( strncmp(buffer, "AQWLCTXB", 9u) )
  {
    puts("Try again.");
    exit(1);
  }
  puts("Good Job.");
  exit(0);
}
```

程序使用`fread()`函数从文件中读取密码，如果密码经过`complex_function()`函数处理后得到的字符串等于`"AQWLCTXB"`则密码正确。

双击`ignore_me()`函数查看详情，该函数的作用是把用户输入的内容存入`OJKSQYDP.txt`中，主函数随后从该文件中读取数据存入`buffer`。

```python
unsigned int __cdecl ignore_me(int a1, size_t n)
{
  void *v2; // esp
  _BYTE v4[12]; // [esp+0h] [ebp-28h] BYREF
  void *ptr; // [esp+Ch] [ebp-1Ch]
  size_t v6; // [esp+10h] [ebp-18h]
  void *s; // [esp+14h] [ebp-14h]
  FILE *stream; // [esp+18h] [ebp-10h]
  unsigned int v9; // [esp+1Ch] [ebp-Ch]

  ptr = (void *)a1;
  v9 = __readgsdword(0x14u);
  v6 = n - 1;
  v2 = alloca(16 * ((n + 15) / 0x10));
  s = v4;
  memset(v4, 0, n);
  unlink("OJKSQYDP.txt");
  stream = fopen("OJKSQYDP.txt", "a+b");
  fwrite(ptr, 1u, n, stream);
  fseek(stream, 0, 0);
  __isoc99_fscanf(stream, "%64s", s);
  fseek(stream, 0, 0);
  fwrite(s, 1u, n, stream);
  fclose(stream);
  return __readgsdword(0x14u) ^ v9;
}
```

双击`complex_function()`函数查看详情：

```c
int __cdecl complex_function(int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (17 * a2 + a1 - 65) % 26 + 65;
}
```

我们需要使用Angr模拟一个文件系统，设置密码的文件名和大小，创建一个符号变量作为密码，使用`Claripy`模块的`BVS`函数创建符号变量`password`，`file_size_bytes*8`指定密码的位数，接着用`SimFile`创建一个包含密码的仿真文件，并利用`fs.insert`将其插入到初始状态的文件系统中。编写`Python`代码求解得到`AZOMMMZM`。

```python
import angr
import claripy

path_to_binary = './07_angr_symbolic_file'
project = angr.Project(path_to_binary, auto_load_libs=False)
start_address = 0x80488D6
initial_state = project.factory.blank_state(
    addr = start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)
filename = 'OJKSQYDP.txt'
file_size_bytes = 64
password = claripy.BVS('password', file_size_bytes*8)
passwd_file = angr.storage.SimFile(filename, content=password, size=file_size_bytes)
initial_state.fs.insert(filename, passwd_file)
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.solver.eval(password, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: {}'.format(passwd))
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python ./07_angr_symbolic_file.py
[+] Congratulations! Solution is: AZOMMMZM

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./07_angr_symbolic_file                                                                         
Enter the password: AZOMMMZM
Good Job.
```

------

### 08_angr_constraints

先用`file ./08_angr_constraints`查看文件类型，并用`checksec ./08_angr_constraints`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./08_angr_constraints                       
./08_angr_constraints: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3c61d9f5ff23e1919a2f19f7e1a9c67e3f2be7e4, not stripped
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./08_angr_constraints   
[*] '/home/tyd/ctf/Angr_CTF/08_angr_constraints'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`08_angr_constraints`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+Ch] [ebp-Ch]

  qmemcpy(&password, "AUPDNNPROEZRJWKB", 16);
  memset(&buffer, 0, 0x11u);
  printf("Enter the password: ");
  __isoc99_scanf("%16s", &buffer);
  for ( i = 0; i <= 15; ++i )
    *(_BYTE *)(i + 134520912) = complex_function(*(char *)(i + 134520912), 15 - i);
  if ( check_equals_AUPDNNPROEZRJWKB(&buffer, 16) )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

该程序将字符串`"AUPDNNPROEZRJWKB"`拷贝到变量`password`中，随后用`memset()`将变量`buffer`初始化为`0x11`个零字节。`scanf`函数读取用户输入的字符串，最多读取16个字符，并将其存储到变量`buffer`中。调用`check_equals_AUPDNNPROEZRJWKB`函数，将`buffer`和长度`16`作为参数传递给它。如果返回值为真，则密码匹配输出`"Good Job."`，否则输出`"Try again."`。`buffer`变量在`.bss`段上：

```assembly
.bss:0804A050                 public buffer
.bss:0804A050 buffer          db    ? ;               ; DATA XREF: main+40↑o
```

双击`complex_function()`函数查看详情。

```c
int __cdecl complex_function(int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (a1 - 65 + 53 * a2) % 26 + 65;
}
```

双击`check_equals_AUPDNNPROEZRJWKB()`函数查看详情。该函数实际上是将主函数中传入的`buffer`和`password`进行比值操作。

```c
_BOOL4 __cdecl check_equals_AUPDNNPROEZRJWKB(int a1, unsigned int a2)
{
  int v3; // [esp+8h] [ebp-8h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  v3 = 0;
  for ( i = 0; i < a2; ++i )
  {
    if ( *(_BYTE *)(i + a1) == *(_BYTE *)(i + 134520896) )
      ++v3;
  }
  return v3 == a2;
}
```

我们可以跳过`scanf()`选择`0x8048625`创建初始状态。

```assembly
.text:08048613                 push    offset buffer
.text:08048618                 push    offset a16s     ; "%16s"
.text:0804861D                 call    ___isoc99_scanf
.text:08048622                 add     esp, 10h
.text:08048625                 mov     [ebp+var_C], 0
.text:0804862C                 jmp     short loc_8048663
```

我们需要保证程序运行到地址`0x08048565`处执行 `check_equals_AUPDNNPROEZRJWKB` 函数时，`buffer` 地址`0x804A050`中存放的内容和字符串 `AUPDNNPROEZRJWKB` 相同，因此可以直接添加条件判断求解。编写`Python`代码求解得到`LGCRCDGJHYUNGUJB`。

```python
import angr
import claripy

path_to_binary = './08_angr_constraints'
project = angr.Project(path_to_binary, auto_load_libs=False)
start_address = 0x8048625
initial_state = project.factory.blank_state(
    addr = start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)
passwd_bytes = 0x10
char_size_bits = 0x8
password = claripy.BVS('password', passwd_bytes*char_size_bits)
buffer_address = 0x804A050
initial_state.memory.store(buffer_address, password)
simulation = project.factory.simgr(initial_state)
check_address = 0x8048565  # check_equals_AUPDNNPROEZRJWKB()
constrained_value = b'AUPDNNPROEZRJWKB' # If the value is equal to "AUPDNNPROEZRJWKB", WARNING: BVV value is being coerced from a unicode string, encoding as utf-8.
simulation.explore(find=check_address)
if simulation.found:
    solution_state = simulation.found[0]
    buffer_content = solution_state.memory.load(buffer_address, passwd_bytes)
    solution_state.solver.add(buffer_content == constrained_value)
    passwd = solution_state.solver.eval(password, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: {}'.format(passwd))
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 08_angr_constraints.py
[+] Congratulations! Solution is: LGCRCDGJHYUNGUJB

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./08_angr_constraints  
Enter the password: LGCRCDGJHYUNGUJB
Good Job.
```

------

### 09_angr_hooks

先用`file ./09_angr_hooks`查看文件类型，并用`checksec ./09_angr_hooks`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./09_angr_hooks                                                                                 
./09_angr_hooks: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=0ae8a2b66c13ff8c3d18656da5cb251317b162e5, not stripped
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./09_angr_hooks      
[*] '/home/tyd/ctf/Angr_CTF/09_angr_hooks'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`09_angr_hooks`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BOOL4 v3; // eax
  int i; // [esp+8h] [ebp-10h]
  int j; // [esp+Ch] [ebp-Ch]

  qmemcpy(password, "XYMKBKUHNIQYNQXE", 16);
  memset(buffer, 0, 0x11u);
  printf("Enter the password: ");
  __isoc99_scanf("%16s", buffer);
  for ( i = 0; i <= 15; ++i )
    *(_BYTE *)(i + 134520916) = complex_function(*(char *)(i + 134520916), 18 - i);
  equals = check_equals_XYMKBKUHNIQYNQXE(buffer, 16);
  for ( j = 0; j <= 15; ++j )
    *(_BYTE *)(j + 134520900) = complex_function(*(char *)(j + 134520900), j + 9);
  __isoc99_scanf("%16s", buffer);
  v3 = equals && !strncmp(buffer, password, 0x10u);
  equals = v3;
  if ( v3 )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

程序将字符串`"XYMKBKUHNIQYNQXE"`拷贝到变量`password`中，并使用`memset`将变量`buffer`初始化为17个零字节。随后用`scanf`函数读取用户输入的字符串，最多读取16个字符，并将其存储到变量`buffer`中。调用`check_equals_XYMKBKUHNIQYNQXE`函数，将`buffer`和长度16作为参数传递给它，并将返回值赋给`equals`变量。再次使用`scanf`函数读取用户输入的字符串，最多读取16个字符，并将其存储到变量`buffer`中。将`equals`与`!strncmp(buffer, password, 0x10u)`的结果进行逻辑与运算，若结果为真则表示密码正确。

双击`complex_function()`函数查看详情。

```c
int __cdecl complex_function(int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (a1 - 65 + 23 * a2) % 26 + 65;
}
```

双击`check_equals_XYMKBKUHNIQYNQXE()`函数查看详情。

```c
_BOOL4 __cdecl check_equals_XYMKBKUHNIQYNQXE(int a1, unsigned int a2)
{
  int v3; // [esp+8h] [ebp-8h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  v3 = 0;
  for ( i = 0; i < a2; ++i )
  {
    if ( *(_BYTE *)(i + a1) == *(_BYTE *)(i + 134520900) )
      ++v3;
  }
  return v3 == a2;
}
```

上一道题中我们使用增加条件约束的方法来减少符号执行的路径分支，而在这题中我们直接利用`hook`来改写程序，具体操作如下：

- `@project.hook(check_address, length = skip_len_bytes)`装饰器将自定义`hook`函数与指定地址关联，以便执行`hook`逻辑。
- 自定义`hook`函数`skip_check_equal()`，用于在指定地址`check_address`处进行`hook`，而`length`决定了要覆盖的指令字节数，或者说是要跳过的指令字节数。
- `skip_check_equal()`函数中使用 `state.memory` 的 `.load(addr, size)`方法读出`buffer`处的内存数据，并进行比值操作。如果判断出`buffer == 'XYMKBKUHNIQYNQXE'`为真则将`$eax`寄存器设置为`1`，否则将`$eax`寄存器设置为`0`。

编写`Python`代码求解得到`ZXIDRXEORJOTFFJNWUFAOUBLOGLQCCGK`。

```python
import angr
import claripy

path_to_binary = './09_angr_hooks'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
check_address = 0x80486B3  # check_equals_XYMKBKUHNIQYNQXE
skip_len_bytes = 5
@project.hook(check_address, length=skip_len_bytes)
def skip_check_equal(state):
    buffer_address = 0x804A054
    passwd_bytes = 0x10
    buffer_content = state.memory.load(buffer_address, passwd_bytes)
    constrained_value = b'XYMKBKUHNIQYNQXE'
    register_size_bits = 32
    state.regs.eax = claripy.If(
        buffer_content == constrained_value,
        claripy.BVV(1, register_size_bits),   # 若判断条件为真则将$eax寄存器设置为1
        claripy.BVV(0, register_size_bits)    # 否则将$eax寄存器设置为0
    )

simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()
    print('[+] Congratulations! Solution is: {}'.format(passwd))
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 09_angr_hooks.py      
[+] Congratulations! Solution is: ZXIDRXEORJOTFFJNWUFAOUBLOGLQCCGK
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./09_angr_hooks        
Enter the password: ZXIDRXEORJOTFFJNWUFAOUBLOGLQCCGK
Good Job.
```

------

### 10_angr_simprocedures

先用`file ./10_angr_simprocedures`查看文件类型，并用`checksec ./10_angr_simprocedures`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./10_angr_simprocedures
./10_angr_simprocedures: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f68c208bfdc6b9b1bb43f81e10e4aa5810a10cfa, not stripped
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./10_angr_simprocedures
[*] '/home/tyd/ctf/Angr_CTF/10_angr_simprocedures'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`10_angr_simprocedures`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+20h] [ebp-28h]
  char s[17]; // [esp+2Bh] [ebp-1Dh] BYREF
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  memcpy(&password, "ORSDDWXHZURJRBDH", 0x10u);
  memset(s, 0, sizeof(s));
  printf("Enter the password: ");
  __isoc99_scanf("%16s", s);
  for ( i = 0; i <= 15; ++i )
    s[i] = complex_function(s[i], 18 - i);
  if ( check_equals_ORSDDWXHZURJRBDH(s, 16) )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

这题跟上题很相似，但是这题的对`check_equals_ORSDDWXHZURJRBDH()`调用点有很多，使人难以每次都对地址进行`hook`，我们可以直接钩取函数，声明一个类并定义`run()`方法来取代想要钩取的函数，然后调用`project.hook_symbol()`方法直接以函数名为参数进行钩取函数，`Angr`会自动查找与目标函数符号关联的地址并执行`hook`操作。编写`Python`代码求解得到`MSWKNJNAVTTOZMRY`。

```python
import angr
import claripy

path_to_binary = './10_angr_simprocedures'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
check_equal_symbol = 'check_equals_ORSDDWXHZURJRBDH'
class CheckEqual(angr.SimProcedure):
    def run(self, address, length):
        constrained_value = b'ORSDDWXHZURJRBDH'
        content = self.state.memory.load(address, length)
        return claripy.If(content == constrained_value, claripy.BVV(1, 32), claripy.BVV(0, 32))

project.hook_symbol(check_equal_symbol, CheckEqual())
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()
    print('[+] Congratulations! Solution is: {}'.format(passwd))
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 10_angr_simprocedures.py      
[+] Congratulations! Solution is: MSWKNJNAVTTOZMRY
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./10_angr_simprocedures
Enter the password: MSWKNJNAVTTOZMRY
Good Job.
```

------

### 11_angr_sim_scanf

先用`file ./11_angr_sim_scanf`查看文件类型，并用`checksec ./11_angr_sim_scanf`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./11_angr_sim_scanf         
./11_angr_sim_scanf: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=04d5fb026631b84a4dfdc2ad047ac6e30b0ecf17, not stripped
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./11_angr_sim_scanf    
[*] '/home/tyd/ctf/Angr_CTF/11_angr_sim_scanf'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`11_angr_sim_scanf`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+20h] [ebp-28h]
  char s[20]; // [esp+28h] [ebp-20h] BYREF
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  memset(s, 0, sizeof(s));
  qmemcpy(s, "SUQMKQFX", 8);
  for ( i = 0; i <= 7; ++i )
    s[i] = complex_function(s[i], i);
  printf("Enter the password: ");
  __isoc99_scanf("%u %u", buffer0, buffer1);
  if ( !strncmp(buffer0, s, 4u) && !strncmp(buffer1, &s[4], 4u) )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

跟上题类似，我们需要对`scanf()`函数进行`hook`操作。在 [**05_angr_symbolic_memory**](05_angr_symbolic_memory) 中已经学习过如何符号化内存啦，在这题中`scanf()`函数是要向内存中写入数据的，所以我们要用`state.memory`模块的`.store(addr, val)`方法将符号位向量写入那俩个字符串的内存区域。编写`Python`代码求解得到`1448564819 1398294103`。然而这题直接用 [**00_angr_find**](#00_angr_find) 中的方法无脑梭哈也能解答。

```python
import angr
import claripy

path_to_binary = './11_angr_sim_scanf'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
scanf_symbol = '__isoc99_scanf'
class ReplaceScanf(angr.SimProcedure):
    def run(self, format_string, param0, param1):
        scanf0 = claripy.BVS('scanf0', 32)
        scanf1 = claripy.BVS('scanf1', 32)
        scanf0_addr = param0
        self.state.memory.store(scanf0_addr, scanf0, endness=project.arch.memory_endness)
        scanf1_addr = param1
        self.state.memory.store(scanf1_addr, scanf1, endness=project.arch.memory_endness)
        self.state.globals['solutions'] = (scanf0, scanf1)

project.hook_symbol(scanf_symbol, ReplaceScanf())
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    (solution0, solution1) = solution_state.globals['solutions']
    passwd0 = solution_state.solver.eval(solution0)
    passwd1 = solution_state.solver.eval(solution1)
    print('[+] Congratulations! Solution is: {} {}'.format(passwd0, passwd1))
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 11_angr_sim_scanf.py
WARNING  | 2023-07-13 17:52:33,347 | angr.project   | Address is already hooked, during hook(0x8100018, <SimProcedure ReplaceScanf>). Re-hooking.                                                                   
[+] Congratulations! Solution is: 1448564819 1398294103

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./11_angr_sim_scanf    
Enter the password: 1448564819 1398294103
Good Job.
```

------

### 12_angr_veritesting

先用`file ./12_angr_veritesting`查看文件类型，并用`checksec ./12_angr_veritesting`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./12_angr_veritesting
./12_angr_veritesting: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7687fe588ecd0d96f86d97f7bc57c00e6820a254, not stripped
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./12_angr_veritesting
[*] '/home/tyd/ctf/Angr_CTF/12_angr_veritesting'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`12_angr_veritesting`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ebx
  int v5; // [esp-14h] [ebp-60h]
  int v6; // [esp-10h] [ebp-5Ch]
  int v7; // [esp-Ch] [ebp-58h]
  int v8; // [esp-8h] [ebp-54h]
  int v9; // [esp-4h] [ebp-50h]
  const char **v10; // [esp+0h] [ebp-4Ch]
  int v11; // [esp+4h] [ebp-48h]
  int v12; // [esp+8h] [ebp-44h]
  int v13; // [esp+Ch] [ebp-40h]
  int v14; // [esp+10h] [ebp-3Ch]
  int v15; // [esp+10h] [ebp-3Ch]
  int v16; // [esp+14h] [ebp-38h]
  int i; // [esp+14h] [ebp-38h]
  int v18; // [esp+18h] [ebp-34h]
  _DWORD v19[9]; // [esp+1Ch] [ebp-30h] BYREF
  unsigned int v20; // [esp+40h] [ebp-Ch]
  int *v21; // [esp+44h] [ebp-8h]

  v21 = &argc;
  v10 = argv;
  v20 = __readgsdword(0x14u);
  memset((char *)v19 + 3, 0, 0x21u);
  printf("Enter the password: ");
  ((void (__stdcall *)(const char *, char *, int, int, int, int, int, const char **, int, int, int, int, int, int, _DWORD))__isoc99_scanf)(
    "%32s",
    (char *)v19 + 3,
    v5,
    v6,
    v7,
    v8,
    v9,
    v10,
    v11,
    v12,
    v13,
    v14,
    v16,
    v18,
    v19[0]);
  v15 = 0;
  for ( i = 0; i <= 31; ++i )
  {
    v3 = *((char *)v19 + i + 3);
    if ( v3 == complex_function(75, i + 93) )
      ++v15;
  }
  if ( v15 != 32 || (_BYTE)v20 )
    puts("Try again.");
  else
    puts("Good Job.");
  return 0;
}
```

这题很容易产生路径爆炸：

```c
for ( i = 0; i <= 31; ++i )
{
    v3 = *((char *)v19 + i + 3);
    if ( v3 == complex_function(75, i + 93) )
      ++v15;
}
```

我们可以启用`Veritesting=True`来让符号执行引起在动态符号执行 `DSE` 和静态符号执行 `SSE` 之间协同工作从而减少路径爆炸的问题。编写`Python`代码求解得到`CXSNIDYTOJEZUPKFAVQLGBWRMHCXSNID`。

```python
import angr

path_to_binary = './12_angr_veritesting'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state, veritesting=True)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()
    print('[+] Congratulations! Solution is: %s' % passwd)
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。可能需要多运行几次才能计算出结果。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 12_angr_veritesting.py      
[+] Congratulations! Solution is: OQSUWYACEGIKMOQSUWYACEGIKMOQSUWY

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./12_angr_veritesting
Enter the password: OQSUWYACEGIKMOQSUWYACEGIKMOQSUWY
Good Job.
```

------

### 13_angr_static_binary

先用`file ./13_angr_static_binary`查看文件类型，并用`checksec ./13_angr_static_binary`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./13_angr_static_binary
./13_angr_static_binary: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=89d11f111deddc580fac3d22a1f6c352d1883cd5, not stripped
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./13_angr_static_binary
[*] '/home/tyd/ctf/Angr_CTF/13_angr_static_binary'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`13_angr_static_binary`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+1Ch] [ebp-3Ch]
  int j; // [esp+20h] [ebp-38h]
  char v6[20]; // [esp+24h] [ebp-34h] BYREF
  char v7[20]; // [esp+38h] [ebp-20h] BYREF
  unsigned int v8; // [esp+4Ch] [ebp-Ch]

  v8 = __readgsdword(0x14u);
  for ( i = 0; i <= 19; ++i )
    v7[i] = 0;
  qmemcpy(v7, "PYIEFPIC", 8);
  printf("Enter the password: ");
  _isoc99_scanf("%8s", v6);
  for ( j = 0; j <= 7; ++j )
    v6[j] = complex_function(v6[j], j);
  if ( !strcmp(v6, v7) )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

双击`complex_function()`函数查看详情：

```c
int __cdecl complex_function(int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (37 * a2 + a1 - 65) % 26 + 65;
}
```

这题求解真正需要用的函数只有`printf`，`scanf`，`puts`，即完成`angr`所需的输出、输入、路径选择的功能，在`IDA Pro`中找出地址：

```assembly
.text:0804ED40                 public printf
.text:0804ED40 printf          proc near               ; CODE XREF: print_msg+13↑p
.text:0804ED40                                         ; main+5A↑p

.text:0804ED80                 public __isoc99_scanf
.text:0804ED80 __isoc99_scanf  proc near               ; CODE XREF: main+6E↑p

.text:0804F350                 public puts ; weak
.text:0804F350 puts            proc near               ; CODE XREF: complex_function+1A↑p
.text:0804F350                                         ; main+D1↑p ...

text:08048D10 ; int __cdecl _libc_start_main(int (__cdecl *main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void *stack_end)
.text:08048D10                 public __libc_start_main
.text:08048D10 __libc_start_main proc near             ; CODE XREF: _start+1C↑p
```

此外`Linux`中`C`程序启动的过程是一定需要用到`__libc_start_main`的。

- `execve` 开始执行。
- `execve` 内部把bin程序加载后，会把`.interp`指定的 动态加载器加载。
- 动态加载器把需要加载的`so`都加载起来，特别的把 `libc.so.6` 加载。
- 调用到`libc.so.6`里的`__libc_start_main`函数，真正开始执行程序，调用`main()`函数。

编写`Python`代码求解得到`PNMXNMUD`。

```python
import angr

path_to_binary = './13_angr_static_binary'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
project.hook(0x804ed40, angr.SIM_PROCEDURES['libc']['printf']())
project.hook(0x804ed80, angr.SIM_PROCEDURES['libc']['scanf']())
project.hook(0x804f350, angr.SIM_PROCEDURES['libc']['puts']())
project.hook(0x8048d10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())
simulation = project.factory.simgr(initial_state, veritesting=True)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()
    print('[+] Congratulations! Solution is: %s' % passwd)
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 13_angr_static_binary.py
[+] Congratulations! Solution is: PNMXNMUD

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./13_angr_static_binary              
Enter the password: PNMXNMUD
Good Job.
```

------

### 14_angr_shared_library

先用`file ./14_angr_shared_library`查看文件类型，并用`checksec ./14_angr_shared_library`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./14_angr_shared_library
./14_angr_shared_library: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3184fc82e0803b9c64f405d2e1924810e71110c7, not stripped
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./14_angr_shared_library
[*] '/home/tyd/ctf/Angr_CTF/14_angr_shared_library'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`14_angr_shared_library`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[16]; // [esp+1Ch] [ebp-1Ch] BYREF
  unsigned int v5; // [esp+2Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(s, 0, sizeof(s));
  printf("Enter the password: ");
  __isoc99_scanf("%8s", s);
  if ( validate(s, 8) )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

双击`validate()`函数查看详情：

```c
// attributes: thunk
int __cdecl validate(int a1, int a2)
{
  return validate(a1, a2);
}
```

无法查看源码，因为这是一个外部导入函数，其源代码在它所处的库文件`lib14_angr_shared_library.so`中。用`IDA`打开库文件进行分析能够找到`validate()`函数的具体实现代码。

```c
_BOOL4 __cdecl validate(char *s1, int a2)
{
  char *v3; // esi
  char s2[4]; // [esp+4h] [ebp-24h]
  int v5; // [esp+8h] [ebp-20h]
  int j; // [esp+18h] [ebp-10h]
  int i; // [esp+1Ch] [ebp-Ch]

  if ( a2 <= 7 )
    return 0;
  for ( i = 0; i <= 19; ++i )
    s2[i] = 0;
  *(_DWORD *)s2 = 'GKLW';
  v5 = 'HWJL';
  for ( j = 0; j <= 7; ++j )
  {
    v3 = &s1[j];
    *v3 = complex_function(s1[j], j);
  }
  return strcmp(s1, s2) == 0;
}
```

双击`complex_function()`函数查看详情：

```c
int __cdecl complex_function(signed int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (41 * a2 + a1 - 65) % 26 + 65;
}
```

我们调用`.call_state`创建`state`对象，构造一个已经准备好执行`validate()`函数的状态，同时需要设定好`validate()`传入的参数，其函数声明为`validate(char *s1, int a2)`。我们可以通过`BVV(value,size)` 和 `BVS( name, size)`创建位向量，将缓冲区地址设定在`0x3000000`，而`32`位程序里`int`型为`4`字节，即`32`比特。从IDA中不难得出`validate`的偏移量为`0x6D7`，因为需要比较的字符串长度为`8`，故利用`BVV`传入参数`int a2`。然后利用`BVS`创建一个符号位向量，作为符号化字符串传入我们之前设定好的缓冲区地址中。编写`Python`代码求解得到`WWGNDMKG`。

```python
import angr
import claripy

path_to_binary = './lib14_angr_shared_library.so'
base_address = 0x8048000
project = angr.Project(path_to_binary, load_options={
    'main_opts': {
        'base_addr': base_address
    }
})
buffer_pointer = claripy.BVV(0x3000000, 32)
validate_address = base_address + 0x6d7
initial_state = project.factory.call_state(
    validate_address, buffer_pointer, claripy.BVV(8, 32),
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
password = claripy.BVS('password', 64)
initial_state.memory.store(buffer_pointer, password)
simulation = project.factory.simgr(initial_state)
success_address = base_address + 0x783
simulation.explore(find=success_address)
if simulation.found:
    solution_state = simulation.found[0]
    solution_state.add_constraints(solution_state.regs.eax != 0)
    passwd = solution_state.solver.eval(password, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: %s' % passwd)
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 14_angr_shared_library.py
WARNING  | 2023-07-14 16:16:56,496 | angr.calling_conventions | Guessing call prototype. Please specify prototype.                                                                                                  
[+] Congratulations! Solution is: WWGNDMKG

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ export LD_LIBRARY_PATH=/home/tyd/ctf/Angr_CTF:$LD_LIBRARY_PATH
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./14_angr_shared_library                                      
Enter the password: WWGNDMKG
Good Job.
```

------

### 15_angr_arbitrary_read

先用`file ./15_angr_arbitrary_read`查看文件类型，并用`checksec ./15_angr_arbitrary_read`查看文件信息。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ file ./15_angr_arbitrary_read
./15_angr_arbitrary_read: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=dbdc748680fa2f82d95a379e7243264d1f699949, not stripped
                                                                                                          
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ checksec ./15_angr_arbitrary_read
[*] '/home/tyd/ctf/Angr_CTF/15_angr_arbitrary_read'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用`IDA Pro 32bit`打开二进制文件`15_angr_arbitrary_read`，按`F5`反汇编源码并查看主函数。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+Ch] [ebp-1Ch] BYREF
  char *s; // [esp+1Ch] [ebp-Ch]

  s = try_again;
  printf("Enter the password: ");
  __isoc99_scanf("%u %20s", &key, &v4);
  if ( key == 36134347 || key != 41810812 )
    puts(try_again);
  else
    puts(s);
  return 0;
}
```

这道题需要通过输入数字和字符串将程序溢出达到任意读的目的。首先我们需要像前几题一样对`scanf()`函数进行`hook`操作，程序输出的函数使用的是`puts`，我们可以添加约束条件检查它输出的字符串是否为`"Good Job."`，具体来说是判断`puts`的第一个参数（指向被打印字符串的指针）是否能被修改为`"Good Job."`的地址。编写`Python`代码求解得到`41810812 CCCCCCCCCCCCCCCCGJOH`。

```python
import angr
import claripy

path_to_binary = './15_angr_arbitrary_read'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
scanf_symbol = '__isoc99_scanf'
class ReplaceScanf(angr.SimProcedure):
    def run(self, format_string, param0, param1):
        scanf0 = claripy.BVS('scanf0',  32)
        scanf1 = claripy.BVS('scanf1', 20*8)
        for ch in scanf1.chop(bits=8):
            self.state.add_constraints(ch >= '0', ch <='z')
        scanf0_address = param0
        self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
        scanf1_address = param1
        self.state.memory.store(scanf1_address, scanf1)
        self.state.globals['solutions'] = (scanf0, scanf1)

project.hook_symbol(scanf_symbol, ReplaceScanf())

def check_puts(state):
    puts_parameter = state.memory.load(state.regs.esp+4, 4, endness=project.arch.memory_endness)
    if state.solver.symbolic(puts_parameter):
        goodjob_address = 0x484F4A47
        copied_state = state.copy()
        copied_state.add_constraints(puts_parameter == goodjob_address)
        if copied_state.satisfiable():
            state.add_constraints(puts_parameter == goodjob_address)
            return True
        else:
            return False
    else:
        return False

simulation = project.factory.simgr(initial_state)
puts_plt = project.loader.main_object.plt['puts']  # 0x8048370
is_succcessful = lambda state: check_puts(state) if state.addr == puts_plt else False
simulation.explore(find=is_succcessful)
if simulation.found:
    solution_state = simulation.found[0]
    (solution0, solution1) = solution_state.globals['solutions']
    passwd0 = solution_state.solver.eval(solution0)
    passwd1 = solution_state.solver.eval(solution1, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: {} {}'.format(passwd0, passwd1))
else:
    raise Exception('Could not find the solution')
```

运行程序进行验证无误。

```bash
┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ python 15_angr_arbitrary_read.py
WARNING  | 2023-07-15 10:59:30,039 | angr.project   | Address is already hooked, during hook(0x4850000c, <SimProcedure ReplaceScanf>). Re-hooking.
[+] Congratulations! Solution is: 41810812 CCCCCCCCCCCCCCCCGJOH

┌──(angr)─(tyd㉿kali-linux)-[~/ctf/Angr_CTF]
└─$ ./15_angr_arbitrary_read        
Enter the password: 41810812 CCCCCCCCCCCCCCCCGJOH
Good Job.
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

