#### 安装docker

```bash
# 在Kali Linux中安装必要的工具
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg lsb-release -y
# 添加Docker官方的GPG密钥
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
# 更新源
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian stretch stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
# 直接导入证书
sudo apt-get update
sudo apt-get install apt-transport-https ca-certificates curl gnupg2 software-properties-common
# 安装docker
sudo apt-get update
sudo apt-get install docker.io docker-compose -y
# 查看docker版本 检查是否安装成功
docker -v
```

`sudo vim /etc/docker/daemon.json`填入以下内容可以更改`docker`源：

```json
{
    "registry-mirrors" : [
    "https://registry.docker-cn.com",
    "http://hub-mirror.c.163.com",
    "https://docker.mirrors.ustc.edu.cn",
    "https://cr.console.aliyun.com",
    "https://mirror.ccs.tencentyun.com"
  ]
}
```

配置完成后重启服务才可以生效。

```bash
sudo systemctl daemon-reload
sudo systemctl restart docker.service
```

随后输入`sudo docker info`可以在`Registry Mirrors:`中看到`docker`源信息。

##### 常用docker命令

```bash
$ service docker start  # 启动docker服务
$ sudo docker version   # 查看docker版本信息
$ sudo docker ps        # 查看容器
$ sudo docker images    # 查看已有的镜像
```

**`dock run` 命令**

```bash
sage:  docker run [OPTIONS] IMAGE [COMMAND] [ARG...]

Run a command in a new container

Options:
      --add-host list                  Add a custom host-to-IP mapping (host:ip)
  -a, --attach list                    Attach to STDIN, STDOUT or STDERR
  -d, --detach                         Run container in background and print container ID
  -e, --env list                       Set environment variables
  -h, --hostname string                Container host name
      --init                           Run an init inside the container that forwards signals and reaps processes
  -i, --interactive                    Keep STDIN open even if not attached
      --ip string                      IPv4 address (e.g., 172.30.100.104)
      --ip6 string                     IPv6 address (e.g., 2001:db8::33)
      --ipc string                     IPC mode to use
      --isolation string               Container isolation technology
      --kernel-memory bytes            Kernel memory limit
  -t, --tty                            Allocate a pseudo-TTY
      --ulimit ulimit                  Ulimit options (default [])
  -u, --user string                    Username or UID (format: <name|uid>[:<group|gid>])
      --userns string                  User namespace to use
      --uts string                     UTS namespace to use
  -v, --volume list                    Bind mount a volume
      --volume-driver string           Optional volume driver for the container
      --volumes-from list              Mount volumes from the specified container(s)
  -w, --workdir string                 Working directory inside the container
```

------

#### 安装vulhub

```bash
wget https://github.com/vulhub/vulhub/archive/master.zip -O vulhub-master.zip
unzip vulhub-master.zip
cd vulhub-master
# 进入漏洞环境所在目录
cd tomcat/CVE-2017-12615
# 编译漏洞环境
sudo docker-compose build
# 运行环境
sudo docker-compose up -d
# 测试结束后删除环境
sudo docker-compose down -v
```

#### 自定义docker容器

编写`Dockerfile`填入以下内容：

```bash
FROM tomcat:8.5

LABEL maintainer="t0ur1st <yaodan.tan@chaintin.com>"
EXPOSE 8080
RUN cd /usr/local/tomcat/conf \
    && LINE=$(nl -ba web.xml | grep '<load-on-startup>1' | awk '{print $1}') \
    && ADDON="<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>" \
    && sed -i "$LINE i $ADDON" web.xml 
```

编写`docker-compose.yml`填入以下内容：

```yml
version: '2'
services:
 tomcat:
   build: .
   ports:
    - "8080:8080"
```

部署`docker`容器。

```bash
# 编译漏洞环境
┌──(tyd㉿Kali)-[~/docker]
└─$ sudo docker-compose build       
[sudo] tyd 的密码：
Building tomcat
Sending build context to Docker daemon  7.168kB
Step 1/4 : FROM tomcat:8.5
 ---> e4dad3adb3fe
Step 2/4 : LABEL maintainer="t0ur1st <yaodan.tan@chaintin.com>"
 ---> Running in f92cb0546c11
Removing intermediate container f92cb0546c11
 ---> ce2e70d86a68
Step 3/4 : EXPOSE 8080
 ---> Running in d77bb7df87e9
Removing intermediate container d77bb7df87e9
 ---> 6ff648669ea7
Step 4/4 : RUN cd /usr/local/tomcat/conf     && LINE=$(nl -ba web.xml | grep '<load-on-startup>1' | awk '{print $1}')     && ADDON="<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>"     && sed -i "$LINE i $ADDON" web.xml
 ---> Running in f2944cef196b
Removing intermediate container f2944cef196b
 ---> 6db320d485db
Successfully built 6db320d485db
Successfully tagged tomcat:8.5

# 运行环境
┌──(tyd㉿Kali)-[~/docker]
└─$ sudo docker-compose up -d
Creating network "docker_default" with the default driver
Creating docker_tomcat_1 ... done

# 查看镜像
┌──(tyd㉿Kali)-[~/docker]
└─$ sudo docker ps                       
CONTAINER ID   IMAGE        COMMAND             CREATED         STATUS         PORTS                                       NAMES
e99dbf4ab2a3   tomcat:8.5   "catalina.sh run"   9 minutes ago   Up 9 minutes   0.0.0.0:8080->8080/tcp, :::8080->8080/tcp   docker_tomcat_1

# 进入镜像环境
┌──(tyd㉿Kali)-[~/docker]
└─$ sudo docker exec -ti e99dbf4ab2a3 bash

# 查看配置文件conf/web.xml中readonly的设置        
root@e99dbf4ab2a3:/usr/local/tomcat# cat conf/web.xml | grep readonly  
<!--   readonly            Is this context "read only", so HTTP           -->
<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>
<init-param><param-name>readonly</param-name><param-value>false</param-value></init-param>
```

登录到`Docker Hub`。

```bash
┌──(tyd㉿Kali)-[~/docker]
└─$ sudo docker login
Login with your Docker ID to push and pull images from Docker Hub. If you don't have a Docker ID, head over to https://hub.docker.com to create one.
Username: t0ur1st
Password: 
WARNING! Your password will be stored unencrypted in /root/.docker/config.json.
Configure a credential helper to remove this warning. See
https://docs.docker.com/engine/reference/commandline/login/#credentials-store

Login Succeeded
```

将`docker`容器编译上传。

```bash
sudo docker build -t t0ur1st/jsp-upload .
sudo docker push t0ur1st/jsp-upload
```

使用时再`docker pull`就行。

```bash
sudo docker pull t0ur1st/jsp-upload
```
