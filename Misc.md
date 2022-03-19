# Misc

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
    flag = ''
    for x in s:
        ans += chr(x^i)
    if "flag" in flag:
        print(flag)
```

------

