`RSA`加密算法是一种非对称加密算法，于`1977`年由罗纳德·李维斯特（`Ron Rivest`）、阿迪·萨莫尔（`Adi Shamir`）、伦纳德·阿德曼（`Leonard Adleman`）一起提出的。

`RSA`公开密钥密码体制的原理是：根据数论，寻求两个大素数比较简单，而将它们的乘积进行因式分解却极其困难，因此可以将乘积公开作为加密密钥。**对极大整数做因数分解的难度**决定了`RSA`算法的可靠性，对一极大整数做因数分解愈困难，`RSA`算法愈可靠。

- 任意选取两个不同的大素数p和q计算乘积 `n=pq`

- `n` 的欧拉函数 `φ(n)`： `φ(n)=(p-1)(q-1)`

- 任意选取一个大整数`e`，满足 `gcd(e, φ(n))=1`，整数`e`用做加密钥

- (注意：`gcd`是最大公约数，`e`的选取是很容易的，例如，所有大于`p`和`q`的素数都可用)

- 确定的解密钥`d`，满足`(de) mod φ(n) = 1`

- 公开整数`n`和`e`，秘密保存`d`

- 公钥（`n`，`e`)

- 私钥（`n`，`d`)

**c：密文**
**m：明文**

将明文 `m` 加密成密文`c`：`c = m^e mod n`
将密文 `c` 解密为明文`m`： `m = c^d mod n`

#### 欧拉函数

任意给定正整数` n` ，计算在小于等于` n` 的正整数中，有多少个与` n` 构成互质关系？计算这个值的方法就叫做欧拉函数，以` φ(n)` 表示。

例如，在` 1` 到` 8` 之中，与8形成互质关系的是` 1` 、` 3` 、` 5` 、` 7` ，所以` φ(n)=4` 。

在` RSA` 算法中，欧拉函数对以下定理成立：

- 如果`n`可以分解成两个互质的整数`p`和`q`的乘积，即`n=p×q`，则有：` φ(n) = φ(pq) = φ(p) × φ(q)` 。
- 当` p` 为质数，` φ(p) = p-1` 。

所以有`φ(n) = (p-1) × (q-1)`。

#### 欧拉定理与模反元素

欧拉函数的用处，在于欧拉定理

“**欧拉定理**”指的是：如果两个正整数`a`和`n`互质，则`n`的欧拉函数`φ(n)`可以让下面的等式成立：`a^φ(n)≡1(modn)`。也就是说，`a`的`φ(n)`次方被`n`除的余数为`1`。
模反元素的推导过程如下：

> 根据欧拉定理，有：`a^φ(n) = a × a^(φ(n)−1)≡1(modn)`。
> 令`b=a^(φ(n)−1)`，得：`a × b≡1(modn)`。
> `b`就是`a`的模反元素。
> 所以，如果两个正整数a和n互质，那么一定可以找到整数b使得ab-1被n整除，或者说ab被n除的余数是1。

所以求私钥d的公式：`d*e≡1mod[(p-1)(q-1)]`

其中`{φ(n) = (p-1)(q-1),φ(n) 与e互质，k为正整数}`
可化为：`d= (k*φ(n)+1)/e`。

RSA密钥一般是1024位（安全）

#### 由p,q,dp,dq,c求明文的算法

```python
from gmpy2 import invert

I = gmpy2.invert(q,p)
mp = pow(c,dp,p)
mq = pow(c,dq,q)               #求幂取模运算
m = (((mp-mq)*I)%p)*q+mq       #求明文公式
print(hex(m))          #转为十六进制
```









