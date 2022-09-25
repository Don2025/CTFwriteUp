# Misc

## BUUCTF

### [签到](https://buuoj.cn/challenges#%E7%AD%BE%E5%88%B0)

提交`flag{buu_ctf}`即可。

------

### [金三胖](https://buuoj.cn/challenges#%E9%87%91%E4%B8%89%E8%83%96)

这题的附件是`.gif`文件，查看`gif`的时候发现有一帧出现了`flag`，编写`Python`代码将`gif`动态图按帧分解为多张静态图片。

```python
from PIL import Image, ImageSequence

src = 'aaa.gif'
suffix='png'
with Image.open(src) as img:
    i = 0
    for frame in ImageSequence.Iterator(img):
        i += 1
        frame.save(f"{i}.{suffix}")
```

程序运行结束后，可以在`21.png`看到`flag{`，`51.png`看到`he11o`，`79.png`看到`hongke}`，提交`flag{he11ohongke}`即可。

------

### [二维码](https://buuoj.cn/challenges#%E4%BA%8C%E7%BB%B4%E7%A0%81)

这题的附件是一个二维码，扫描后显示`secret is here`，并没有什么信息。用`WinHex`打开发现`4number.txt`，盲猜文件里含有`.txt`文件，使用命令行`foremost -i QR_code.png`或者`binwalk -e QR_code.png`可以分离出图片和压缩包，压缩包被加密啦。

使用`fcrackzip`对压缩包进行爆破，根据`4number.txt`这一提示可知密码是4位数字。`fcrackzip`的一些参数如下：

> -b 表示使用暴力破解的方式
>
> -c 'aA1'表示使用大小写字母和数字混合破解的方式
>
> -l 1-16 表示需要破解的密码长度为1~10位
>
> -u 表示只显示破解出来的密码，尝试错误的密码不被显示

我们采用4位数字的暴力破解的方式可以得出压缩包密码是`7639`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/misc/buuctf]
└─$ fcrackzip -b -c '1' -l 4 -u 1D7.zip

PASSWORD FOUND!!!!: pw == 7639
```

解压缩后打开新的`4number.txt`文件得到`CTF{vjpw_wnoei}`，提交`flag{vjpw_wnoei}`即可。

------

### [你竟然赶我走](https://buuoj.cn/challenges#%E4%BD%A0%E7%AB%9F%E7%84%B6%E8%B5%B6%E6%88%91%E8%B5%B0)

这题附件是一个`.jpg`图片，使用`WinHex`打开文件后，在末尾可以看到相应的`ASCII`码信息`flag IS flag{stego_is_s0_bor1ing}`，提交`flag{stego_is_s0_bor1ing}`即可。也可以用`stegSolve`打开，然后`Analyse`→`File Format`在`Ascii`中发现`flag`。

------

### [N种方法解决](https://buuoj.cn/challenges#N%E7%A7%8D%E6%96%B9%E6%B3%95%E8%A7%A3%E5%86%B3)

这题附件是`KEY.exe`，使用`WinHex`打开文件后，发现`ASCII`码信息如下：

```
data:image/jpg;base64,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
```

直接将以上信息复制到`Google Chrome`的网址输入栏中，按下回车键后可以看到一张二维码图片，使用`QR Research`扫描后可以得到`KEY{dca57f966e4e4e31fd5b15417da63269}`，提交`flag{dca57f966e4e4e31fd5b15417da63269}`即可。

------

### [大白](https://buuoj.cn/challenges#%E5%A4%A7%E7%99%BD)

这题附件是`dabai.png`，用`tweakpng`打开图片会弹出提示框`Incorrect crc for IHDR chunk (is 6d7c7135, should be 8e14dfcf)`，双击`IHDR`的`CRC`，把图片的`Height`设置为和`Width`一样的`679`后保存，重新打开图片可以看到`flag{He1l0_d4_ba1}`。

------

### [基础破解](https://buuoj.cn/challenges#%E5%9F%BA%E7%A1%80%E7%A0%B4%E8%A7%A3)

这题附件是`.rar`压缩包，根据题目描述可知密码是四位数字，暴力破解后发现解压密码是`2563`，解压缩后打开`flag.txt`得到`base64`加密后的字符串，编写`Python`代码进行`base64`解码：

```python
from base64 import *

flag = b64decode('ZmxhZ3s3MDM1NDMwMGE1MTAwYmE3ODA2ODgwNTY2MWI5M2E1Y30=').decode('utf-8')
print(flag) # flag{70354300a5100ba78068805661b93a5c}
```

提交`flag{70354300a5100ba78068805661b93a5c}`即可。

------

### [乌镇峰会种图](https://buuoj.cn/challenges#%E4%B9%8C%E9%95%87%E5%B3%B0%E4%BC%9A%E7%A7%8D%E5%9B%BE)

这题附件是一个`.jpg`图片，使用`WinHex`打开文件后，在末尾可以看到相应的`ASCII`码信息`flag IS flag{stego_is_s0_bor1ing}`，提交`flag{97314e7864a8f62627b26f3f998c37f1}`即可。也可以用`stegSolve`打开，然后`Analyse`→`File Format`在`Ascii`中发现`flag`。

------

### [文件中的秘密](https://buuoj.cn/challenges#%E6%96%87%E4%BB%B6%E4%B8%AD%E7%9A%84%E7%A7%98%E5%AF%86)

这题附件是一个`.jpeg`图片，右键→属性→详细信息，可以在备注看到`flag{870c5a72806115cb5439345d8b014396}`。

------

### [wireshark](https://buuoj.cn/challenges#wireshark)

这题的附件是`.pcap`文件，用`wireshark`打开后，根据题目提示输入`http.request.method==POST`直接过滤出`POST`流量包，可以看到`password`，题目描述说管理员的密码就是答案，因此提交`flag{ffb7567a1d4f4abdffdb54e022f8facd}`即可。

------

### [LSB](https://buuoj.cn/challenges#LSB)

这题的附件是`.png`，根据题目名称，用`StegSolve`打开图片，进行`Data Extract`，`Bit Order`设置`LSB first`，`Bit Planes`勾选`Red 0`，`Green 0`，`Blue 0`，点击`Save Bin`保存覆盖原文件，可以得到一张二维码，使用`QR Research`扫描二维码得到`cumtctf{1sb_i4_s0_Ea4y}`，提交`flag{1sb_i4_s0_Ea4y}`即可。

------

### [rar](https://buuoj.cn/challenges#rar)

这题的附件是`.rar`，根据题目提示可知该`.rar`文件的密码是`4`位纯数字，使用`ARCHPR`对压缩包进行4位纯数字密码爆破可得解压密码为`8795`，解压缩后在`.txt`文件中可以看到`flag{1773c5da790bd3caff38e3decd180eb7}`，提交即可。

------

### Yesec no drumsticks

题目描述：

> Yesec是个老涩逼（lsb），所以要给他扣鸡腿

附件是`.png`，根据题目描述的提示，用`StegSolve`打开图片，进行`Data Extract`，`Bit Order`设置`LSB first`，`Bit Planes`勾选`Red 0`，`Green 0`，`Blue 0`，点击`Preview`预览，可以看到`flag{Yesec_1s_lsb}`，提交即可。

------

### qsdz's girlfriend

题目描述：

> 我失忆了，这是我在我桌面上发现的压缩包，可是我忘记了压缩包密码了...请问你能帮助我找到我女朋友的名字吗？flag格式为：flag{女朋友名字_女朋友生日}

根据题目描述，压缩包的密码很可能是女朋友生日，生日作为密码，可能是`6`位，可能是`8`位，但一定是纯数字，设置好范围后，使用`Advanced Archive Password Recovery`暴力破解，得到密码`20031201`，解压缩后得到一张图片。

![](https://paper.tanyaodan.com/BUUCTF/qsdz's_girlfriend/girlfriend.png)

这是音乐游戏**Arcaea**里的光，`WinHex`打开图片可以在文件末尾看见隐藏信息：

```
TXkgZ2lybGZyaWVuZCdzIG5hbWUgaGFzIHNpeCBsZXR0ZXJzIGFuZCB0aGUgZmlyc3QgbGV0dGVyIGlzIGNhcGl0YWxpemVk
```

`base64`解码得到：

```
My girlfriend's name has six letters and the first letter is capitalized
```

他女朋友名字有六个字母且首字母大写。重新回到韵律源点这款音乐游戏，姓名为“光”的日文“ひかり”所对应的罗马音为“Hikari”。最终构造出`flag`为`flag{Hikari_20031201}`。

------

### EzSnake

题目描述：达到114分即可获得一个一个一个一个flag。题目附件给出一个`EzSnake.jar`文件，直接用[**jd-gui**](https://github.com/java-decompiler/jd-gui)或[**Luyten**](https://github.com/deathmarine/Luyten)这种`jar`包反编译工具打开`jar`包进行解码后，全部保存在文件夹`decompiled-EzSnake`中。用`IDEA`对`decompiled-EzSnake\top\woodwhale\snake\GamePanel.java`文件进行修改，把`114`改成一个很小的数字，比如`1`。重新编译运行项目，如果报错`java: 对Timer的引用不明确`的话，在`GamePanel`中添加以下代码即可：

```java
import javax.swing.Timer;
```

编译运行项目，只要得到一分就能弹出来提示框：

![](https://paper.tanyaodan.com/BUUCTF/EzSnake/1.png)

很明显，这是一张少了三个锚点的二维码，用Photoshop把锚点加上即可识别。

![](https://paper.tanyaodan.com/BUUCTF/EzSnake/2.png)

扫描二维码的结果如下：

```
ZmxhZ3tZMHVfNHJlXzBuZV9vTmVfMG5FX3N0NFJ9=
```

这是一个`base64`字符串，编写`Python`代码进行解码可得`flag{Y0u_4re_0ne_oNe_0nE_st4R}`。

```python
from base64 import *

flag = b64decode('ZmxhZ3tZMHVfNHJlXzBuZV9vTmVfMG5FX3N0NFJ9=').decode()
print(flag) # flag{Y0u_4re_0ne_oNe_0nE_st4R}
```

------



## PwnTheBox

### [迟来的签到题](https://ce.pwnthebox.com/challenges?tag=29&id=962)

题目描述给出的信息如下：

> easy xor???
>
> AAoHAR1XICciX1IlXiBUVFFUIyRRJFRQVyUnVVMnUFcgIiNXXhs=

编写`Python`代码遍历`[0, 256)`进行异或操作，得到`flag{1FAD94C8F2272EB7B261CA35A61FDE18}`。

```python
from base64 import *

s = b64decode('AAoHAR1XICciX1IlXiBUVFFUIyRRJFRQVyUnVVMnUFcgIiNXXhs=')
for i in range(0, 256):
    ans = ''
    for x in s:
        ans += chr(x^i)
    if "flag" in ans:
        print(ans)
```

------

### [对象](https://ce.pwnthebox.com/challenges?type=1&id=497)

打开数据流量包，发现里面有`TCP`和`HTTP`两种协议，直接搜索`flag`没有发现任何信息。挨个观察数据流传输信息，发现大部分数据流都是在传输图片和`gif`，第`188`个数据流是`http`协议数据流，传输的是`text/html`，进行流追踪可以看到 `Hey this is a flag FLAG-GehFMsqCeNvof5szVpB2Dmjx`，提交`FLAG-GehFMsqCeNvof5szVpB2Dmjx`即可。

------

### [文件](https://ce.pwnthebox.com/challenges?type=1&id=149)

这题附件是`key.pcapng`，用`Wireshark`打开数据流量包，发现里面有`TCP`和`HTTP`两种协议，直接输入`http contains "flag"`筛选协议。进行`HTTP`流追踪可以看到`flag{This_is_a_f10g}`，提交即可。

------

### [据说有些数据可以进行多重编码](https://ce.pwnthebox.com/challenges?id=1077)

这题的附件是`.txt`文件，其中内容如下：

```
486d65656d727720516372697a716e7a72707a687271207262205a6278656d7163206e767a612072626b206e65727468706d7863615b32362c34352c31362c35362c31375d2c20686d6b7a657420707a7872706b7a6b2072712061637a2078707a72617a71612068706d617a70206d622061637a205a6278656d716320657262787372787a2072626b2061637a20687670656b2771206e707a2d7a776d627a6261206b70727772616d71612e437a206d71207675617a62206a7265657a6b205a62786572626b2771206272616d76627265206e767a612072626b2061637a20224472706b2076752052677662225b382c32302c33382c31322c37322c34322c332c365d2e436d7120717370676d676d62782068767069712c206d626a65736b6d6278207176777a206a7665657264767072616d7662712c206a7662716d7161207675207264767361203338206e657274712c717662627a61712c206168762065766278206272707072616d677a206e767a77712c2072626b20717a677a707265207661637a70206e767a77712e20436d71206e65727471206372677a20647a7a622061707262716572617a6b206d626176207a677a70742077726c767020656d676d627820657262787372787a2072626b2072707a206e7a70757670777a6b207776707a207675617a62206163726220616376717a20767520726274207661637a70206e65727468706d7863615b31302c36322c31322c35392c332c33382c35312c34352c342c31342c34312c31335d2e0a516372697a716e7a72707a2068727120647670622072626b2070726d717a6b206d622051617072617576706b2d736e76622d526776622e2041637a20697a74206d712076622061636d7120716172787a2e2052612061637a2072787a2076752031382c20637a20777270706d7a6b205262627a2043726163726872742c20686d6163206863767720637a2063726b206163707a7a206a636d656b707a623a20517371726262722c2072626b2061686d627120437277627a612072626b204c736b6d61632e20447a61687a7a6220313538352072626b20313539322c20637a20647a78726220722071736a6a7a7171757365206a72707a7a705b34312c34332c32322c35342c31322c34322c33332c35312c385d206d62204576626b766220727120726220726a6176702c2068706d617a702c2072626b206e727061207668627a702076752072206e6572746d6278206a76776e726274206a7265657a6b2061637a204576706b204a637277647a7065726d62277120577a622c206572617a702069627668622072712061637a20496d6278277120577a622e2041637a20756572782074767320627a7a6b206d7120637a707a3a615474486c545369587a4961677a7351596970684d446467635566616d765a554a444c634d7441427672553d3d2e20437a20726e6e7a727071206176206372677a20707a616d707a6b2061762051617072617576706b2072707673626b20313631332c2068637a707a20637a206b6d7a6b206163707a7a20747a727071206572617a702e20557a6820707a6a76706b7120767520516372697a716e7a72707a2771206e706d6772617a20656d757a20717370676d677a2c2072626b2061637a707a2063727120647a7a62206a7662716d6b7a707264657a20716e7a6a736572616d76622072647673612071736a6320777261617a707120727120636d71206e6374716d6a726520726e6e7a727072626a7a2c20717a667372656d61742c20707a656d786d76737120647a656d7a75712c2072626b2068637a61637a702061637a20687670697120726161706d6473617a6b20617620636d7720687a707a2068706d61617a62206474207661637a70715b31362c34332c33312c332c35342c31322c33332c31352c35395d2e
```

使用`s=bytes.fromhex()`进行`16`进制解码后得到：

```
Hmeemrw Qcrizqnzrpzhrq rb Zbxemqc nvza rbk nerthpmxca[26,45,16,56,17], hmkzet pzxrpkzk rq acz xpzrazqa hpmazp mb acz Zbxemqc erbxsrxz rbk acz hvpek\'q npz-zwmbzba kprwramqa.Cz mq vuazb jreezk Zbxerbk\'q bramvbre nvza rbk acz "Drpk vu Rgvb"[8,20,38,12,72,42,3,6].Cmq qspgmgmbx hvpiq, mbjeskmbx qvwz jveerdvpramvbq, jvbqmqa vu rdvsa 38 nertq,qvbbzaq, ahv evbx brppramgz nvzwq, rbk qzgzpre vaczp nvzwq. Cmq nertq crgz dzzb aprbqerazk mbav zgzpt wrlvp emgmbx erbxsrxz rbk rpz nzpuvpwzk wvpz vuazb acrb acvqz vu rbt vaczp nerthpmxca[10,62,12,59,3,38,51,45,4,14,41,13].\nQcrizqnzrpz hrq dvpb rbk prmqzk mb Qaprauvpk-snvb-Rgvb. Acz izt mq vb acmq qarxz. Ra acz rxz vu 18, cz wrppmzk Rbbz Cracrhrt, hmac hcvw cz crk acpzz jcmekpzb: Qsqrbbr, rbk ahmbq Crwbza rbk Lskmac. Dzahzzb 1585 rbk 1592, cz dzxrb r qsjjzqquse jrpzzp[41,43,22,54,12,42,33,51,8] mb Evbkvb rq rb rjavp, hpmazp, rbk nrpa vhbzp vu r nertmbx jvwnrbt jreezk acz Evpk Jcrwdzpermb\'q Wzb, erazp ibvhb rq acz Imbx\'q Wzb. Acz uerx tvs bzzk mq czpz:aTtHlTSiXzIagzsQYiphMDdgcUfamvZUJDLcMtABvrU==. Cz rnnzrpq av crgz pzampzk av Qaprauvpk rpvsbk 1613, hczpz cz kmzk acpzz tzrpq erazp. Uzh pzjvpkq vu Qcrizqnzrpz\'q npmgraz emuz qspgmgz, rbk aczpz crq dzzb jvbqmkzprdez qnzjseramvb rdvsa qsjc wraazpq rq cmq nctqmjre rnnzrprbjz, qzfsremat, pzemxmvsq dzemzuq, rbk hczaczp acz hvpiq raapmdsazk av cmw hzpz hpmaazb dt vaczpq[16,43,31,3,54,12,33,15,59].
```

接着用 http://www.quipqiup.com/ 进行`quipqiup`解码，得到：

```
William Shakespearewas an English poet and playwright[26,45,16,56,17], widely regarded as the greatest writer in the English language and the world\'s pre-eminent dramatist.He is often called England\'s national poet and the "Bard of Avon"[8,20,38,12,72,42,3,6].His surviving works, including some collaborations, consist of about 38 plays,sonnets, two long narrative poems, and several other poems. His plays have been translated into every major living language and are performed more often than those of any other playwright[10,62,12,59,3,38,51,45,4,14,41,13].\pShakespeare was born and raised in Stratford-upon-Avon. The key is on this stage. At the age of 18, he married Anne Hathaway, with whom he had three children: Susanna, and twins Hamnet and Judith. Between 1585 and 1592, he began a successful career[41,43,22,54,12,42,33,51,8] in London as an actor, writer, and part owner of a playing company called the Lord Chamberlain\'s Men, later known as the King\'s Men. The flag you need is here:tYyWjYUkGeKtveuSZkrwIBbvhFxtioEFCBJhIyTNoaF==. He appears to have retired to Stratford around 1613, where he died three years later. Few records of Shakespeare\'s private life survive, and there has been considerable speculation about such matters as his physical appearance, sexuality, religious beliefs, and whether the works attributed to him were written by others[16,43,31,3,54,12,33,15,59]
```

编写`Python`代码进行异或操作得到`ntio{QAMK-awpoK_ahTDdFl_eoSb_cogpJZCVzbBNn}`。

```python
s = 'tYyWjYUkGeKtveuSZkrwIBbvhFxtioEFCBJhIyTNoaF'
weight = [[26,45,16,56,17],
[8,20,38,12,72,42,3,6],
[10,62,12,59,3,38,51,45,4,14,41,13],
[41,43,22,54,12,42,33,51,8],
[16,43,31,3,54,12,33,15,59]]
weight = sum(weight, [])
flag = [ord(x) ^ y for x, y in zip(s, weight)]
print(bytes(flag)) # ntio{QAMK-awpoK_ahTDdFl_eoSb_cogpJZCVzbBNn}
```

接着进行凯撒密码解密可以得到`flag{ISEC-sohgC_szLVvXd_wgKt_ugyhBRUNrtTFf}`，提交即可。

```python
text = 'ntio{QAMK-awpoK_ahTDdFl_eoSb_cogpJZCVzbBNn}'
flag = ''
for i in range(1, 27):
    s = ''
    for x in text:
        if x.isupper():
            s += chr(ord('A')+(ord(x)-ord('A')+i)%26)
        elif x.islower():
            s += chr(ord('a')+(ord(x)-ord('a')+i)%26)
        else:
            s += x
    if 'flag' in s:
        flag = s
    # print('{}的移位是{}'.format(s, (ord(text[0])-ord(s[0]))%26))

print(flag) # flag{ISEC-sohgC_szLVvXd_wgKt_ugyhBRUNrtTFf}
```

------

