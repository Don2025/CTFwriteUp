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

#### 