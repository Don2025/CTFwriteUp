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

