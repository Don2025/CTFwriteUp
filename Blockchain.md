# Blockchain

## BUUCTF

### Checkin

题目描述如下：

> 简简单单的签到题 （所有Blockchain题目均部署在Goerli测试网）
>
> Goerli水龙头：https://goerlifaucet.com/ 
>
> nc 124.221.212.109 10000

以太坊钱包是帮助我们管理以太坊账户的软件应用程序，它能用来保存私钥、创建以太坊交易数据包并以我们的身份在网络上广播。[**Metamask**](https://metamask.io/)是一个基于浏览器扩展的钱包，它运行在`Web`浏览器中，比如`Chrome`。我们可以使用该钱包去链接多种以太坊节点并测试区块链。注册成功后添加`Goerli`测试网络，并去[**Goerli Faucet**](https://goerlifaucet.com/)领取测试币。

![](https://paper.tanyaodan.com/BUUCTF/Checkin/1.png)

`nc`链接靶机，选择`1`选项创建账户，服务器会给我们一个`deployer account`和`token`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ nc 124.221.212.109 10000
Welcome to Blockchain's world,there is an eazy challenge for you!
Your goal is to make isSolved() function returns true!

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 1
[+] deployer account: 0xd71CD902Ba1d04197D1C59bF24534828cB375b7F
[+] token: v4.local.F1GNQXmK8Za2LJYV3jSOtZFNHumsNOvHV6HdLiErWMRQ7PnBNDRkaLIlRBD3njfYP2K3R4hORUpFRYR134vDTs6Oz0FjRp04Lq7qRpfq10A3-cUF-LiBJuktZHU4ADHd5lxz9oAk51SkEovATNdCn0ylh0uhTawW4wZBb3XGXo47oQ
[+] please transfer 0.001 test ether to the deployer account for next step
```

用`Metamask`向该地址转账`0.001 GoerliETH`。

![](https://paper.tanyaodan.com/BUUCTF/Checkin/2.png)

转账完成后，选择`2`选项，输入`token`部署合约，拿到`contract address`和`transaction hash`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ nc 124.221.212.109 10000
Welcome to Blockchain's world,there is an eazy challenge for you!
Your goal is to make isSolved() function returns true!

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 2
[-] input your token: v4.local.F1GNQXmK8Za2LJYV3jSOtZFNHumsNOvHV6HdLiErWMRQ7PnBNDRkaLIlRBD3njfYP2K3R4hORUpFRYR134vDTs6Oz0FjRp04Lq7qRpfq10A3-cUF-LiBJuktZHU4ADHd5lxz9oAk51SkEovATNdCn0ylh0uhTawW4wZBb3XGXo47oQ
[+] contract address: 0x38A2A8a0aa8efb1b49D9f9E2bCcA94F33b6cfe7D
[+] transaction hash: 0xac761bf32b3e77209a1896c6e79888a68acb30f5879ff80734417dbe09af7807
```

在[**Etherscan**](https://goerli.etherscan.io)中查找对应的交易，也可以看到生成合约的地址。

![](https://paper.tanyaodan.com/BUUCTF/Checkin/3.png)

选择`4`选项查看合约代码，审计代码后发现通过`setGreeting`函数赋值`_greeting = 'HelloNewstarCTF'`后即可解决问题。

```solidity
pragma solidity 0.8.7;

contract Checkin {
    string greeting;

    constructor(string memory _greeting) public {
        greeting = _greeting;
    }

    function greet() public view returns (string memory) {
        return greeting;
    }

    function setGreeting(string memory _greeting) public {
        greeting = _greeting;
    }

    function isSolved() public view returns (bool) {
        string memory key = "HelloNewstarCTF";
        return keccak256(abi.encodePacked(key)) == keccak256(abi.encodePacked(greeting));
    }
}
```

`Solidity`的编译器是一个独立的可执行程序，通常包含在各类编程框架中，也会集成在一些`Ethereum IDE`中，比如[**Remix**](https://remix.ethereum.org)。

我们在`Remix`中新建一个`Checkin.sol`文件，粘贴选项`4`中给出的合约代码后，点击`Compile Checkin.sol`进行编译。

![](https://paper.tanyaodan.com/BUUCTF/Checkin/4.png)

用`Metamask`连接`Remix`后在`At Address`处输入选项`2`中的合约地址后点击`At Address`。

![](https://paper.tanyaodan.com/BUUCTF/Checkin/5.png)

在`Deployed Contracts`的`setGreeting`中给`_greeting`赋值`"HelloNewstarCTF"`，并点击`transact`进行交易。

![](https://paper.tanyaodan.com/BUUCTF/Checkin/6.png)

在`Metamask`中核实交易地址后确认交易，即可与合约地址进行交互。

![](https://paper.tanyaodan.com/BUUCTF/Checkin/7.png)

在[**Etherscan**](https://goerli.etherscan.io/tx/0xf5d58c603a70d6778617c4932f8ae8d76814bf77d5d4aa4d66054f1f1aa6cec5)中查看本次交易，`Click to see More`可以看到`setGreeting(string _greeting)`函数已经被触发啦。

![](https://paper.tanyaodan.com/BUUCTF/Checkin/8.png)

交易完成后，选择`3`选项，输入`token`即可拿到`flag{Ea2y_B1ockChain_Ch3ckin}`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ nc 124.221.212.109 10000
Welcome to Blockchain's world,there is an eazy challenge for you!
Your goal is to make isSolved() function returns true!

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 3
[-] input your token: v4.local.F1GNQXmK8Za2LJYV3jSOtZFNHumsNOvHV6HdLiErWMRQ7PnBNDRkaLIlRBD3njfYP2K3R4hORUpFRYR134vDTs6Oz0FjRp04Lq7qRpfq10A3-cUF-LiBJuktZHU4ADHd5lxz9oAk51SkEovATNdCn0ylh0uhTawW4wZBb3XGXo47oQ
[+] flag: flag{Ea2y_B1ockChain_Ch3ckin}
```

------

### Guess Number

题目描述如下：

> 猜猜数字是什么？
>
> 0x168d2A47c58ae63ea2a2A4c622259c84086f791D@Goerli 
>
> nc 124.221.212.109 10001

`nc`链接靶机，选择`2`选项查看合约代码，审计代码后发现通过`guess`函数赋值使得`guess_number = number`即可触发`isSolved()`函数解决问题。

```solidity
pragma solidity ^0.4.23;

contract guessnumber {
    mapping(address => uint) private answer;
    address owner;
    uint number;
    
    constructor()public{
        owner = msg.sender;
    }

    event isSolved();

    modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }

    function set_number(uint new_number) public onlyOwner{
        number=new_number;
    }

    function guess(uint guess_number) public {
        answer[msg.sender]=guess_number;
        if(answer[msg.sender]==number){
            emit isSolved();
        }
    }
}
```

我们在`Remix`中新建一个`GuessNumber.sol`文件，粘贴选项`2`中给出的合约代码后，点击`Compile GuessNumber.sol`进行编译。

![](https://paper.tanyaodan.com/BUUCTF/GuessNumber/1.png)

由于题目给出的是一个固定地址，可以在[**Etherscan**](https://goerli.etherscan.io/address/0x168d2a47c58ae63ea2a2a4c622259c84086f791d)中看到该地址的交易信息，随意访问一个`Method`为`Guess`的`Txn Hash`，可以看到它是一个交互成功且存在`Logs`项的交易（`Logs`项说明这笔交易触发了事件）。在`Input Data`中可以看到`uint256`型变量`_guess`被赋值为`7810111911511697114678470`。用`Metamask`连接`Remix`后在`At Address`处输入题目描述中的合约地址后点击`At Address`。

![](https://paper.tanyaodan.com/BUUCTF/GuessNumber/2.png)

在`Deployed Contracts`的`guess`中给`guess_number`赋值为`"7810111911511697114678470"`，并点击`transact`进行交易。

![](https://paper.tanyaodan.com/BUUCTF/GuessNumber/3.png)

在`Metamask`中核实交易地址后确认交易，即可与合约地址进行交互。

![](https://paper.tanyaodan.com/BUUCTF/GuessNumber/4.png)

在[**Etherscan**](https://goerli.etherscan.io/tx/0x45c2b7ee162fb3046ef5ec3c813ea9bb3a93f370d2d7d70c5e6ec91f4435891d)中可以查看到本次交易已经触发了`isSolved`事件，复制`Transaction Hash`。

![](https://paper.tanyaodan.com/BUUCTF/GuessNumber/5.png)

交易完成后，选择`1`选项，输入`tx hash`即可拿到`flag{Wh4t_1s_th3_numb3r}`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ nc 124.221.212.109 10001
Just guess the secret number!
Get the flag after isSolved event is emitted！

[1] - Get your flag once you meet the requirement
[2] - Show the contract source code
[-] input your choice: 1
[-] input tx hash that emitted isSolved event: 0x45c2b7ee162fb3046ef5ec3c813ea9bb3a93f370d2d7d70c5e6ec91f4435891d
[+] flag: flag{Wh4t_1s_th3_numb3r}
```

------

### The chosen one

题目描述如下：

> 只有天选之人才能做出这道题，你是其中之一吗？ 
>
> nc 124.221.212.109 10002

查看提示：

> 只有特定尾号的地址才能与合约交互 https://vanity-eth.tk/

`nc`链接靶机，选择`1`选项创建账户，服务器会给我们一个`deployer account`和`token`。

```bash
┌──(tyd㉿kali-linux)-[~/ctf]
└─$ nc 124.221.212.109 10002
Who is the chosen one?
Get the flag after isSolved event is emitted！

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 1
[+] deployer account: 0xaa68C4eB1a7b6224434F5125b8436B161227Bae3
[+] token: v4.local.BjOiqkzMdk1cl8-0PjmXSp1rKdG3WoMmL47Rdi3H7bLnuDV2ZbxanylQBhm3kY_IcSsjuMzXVcxI0ajp_3KTETO0cwp35Cekb5gfEY-zu6LPj0Cw7BSCtrmeo0UlwcfBRRHRNqIA1kFCE9wu3HEdTg3628U4N2aWx-FJk4tJZMtQ3Q
[+] please transfer 0.030 test ether to the deployer account for next step
```

先不着急转账，选择`4`选项查看合约代码，审计代码后发现只有`owner`才有权限调用`getflag()`函数，从而触发`isSolved()`函数解决问题。`Solidity`的内置函数`require`可以用来测试是否满足前提条件，若不满足条件将导致合约执行因异常而停止并退回剩余的`gas`。

`msg`对象是一个所有合约都可以访问的输入，它代表触发这个合约执行的交易。`sender`属性是发起这个交易的发起方地址。当条件`uint(msg.sender) & 0xffff==0xabcd`为真时，即交易发起方的后四位地址为`abcd`时，就能执行`owner = msg.sender;`让当前交易的信息发送者成为`owner`。

```solidity
pragma solidity ^0.4.24;

contract choose {
    address owner;
    
    event isSolved();
    
    constructor() public{
        owner = msg.sender;
    }
    
    function chooseone() public{
        require(uint(msg.sender) & 0xffff==0xabcd);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    function getflag() onlyOwner {
        emit isSolved();
    }
}
```

要想满足该条件就需要一个后四位地址为`abcd`的账户，但是以太坊账户地址都是基于`Hash`算法随机生成的，我们该如何获得后四位地址指定为`abcd`的以太坊账户呢？根据提示访问[**VANITY-ETH**](https://vanity-eth.tk/)，这个网站可以帮助我们获得指定前缀或后缀的以太坊账号。

![](https://paper.tanyaodan.com/BUUCTF/TheChosenOne/1.png)

指定`Suffix`为`abcd`后点击`Generate`，等待了`25`秒后得到了符合要求的账户地址，点击`Save`保存文件。在`Metamask`中以`json`类型导入账户，然后给选项`1`中的地址转账`0.001 GoerliETH`，交易完成后可以在[**Etherscan**](https://goerli.etherscan.io/tx/0xabd0fded3e105bad962349e7e198b2d6e78c4c1d8f7f3d5bf5f46e9a1c69d9e3)中可以查看到本次交易。转账完成后，选择`2`选项，输入`token`部署合约，拿到`contract address`和`transaction hash`。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ nc 124.221.212.109 10002
Who is the chosen one?
Get the flag after isSolved event is emitted！

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 2
[-] input your token: v4.local.BjOiqkzMdk1cl8-0PjmXSp1rKdG3WoMmL47Rdi3H7bLnuDV2ZbxanylQBhm3kY_IcSsjuMzXVcxI0ajp_3KTETO0cwp35Cekb5gfEY-zu6LPj0Cw7BSCtrmeo0UlwcfBRRHRNqIA1kFCE9wu3HEdTg3628U4N2aWx-FJk4tJZMtQ3Q
[+] contract address: 0x57025cAb9EADB43305ADd6F7255a3Fb22E90FA99
[+] transaction hash: 0x2bc71298566b202eef98d43be3d2a34fc06f04c87a1a92c86fc33b609bef6b50
```

然后在`Remix`中新建一个`TheChosenOne.sol`文件，粘贴选项`4`中给出的合约代码后，点击`Compile TheChosenOne.sol`进行编译。

![](https://paper.tanyaodan.com/BUUCTF/TheChosenOne/2.png)

用`Metamask`连接`Remix`后在`At Address`处输入选项`2`中的合约地址后点击`At Address`。

![](https://paper.tanyaodan.com/BUUCTF/TheChosenOne/3.png)

在`Deployed Contracts`中点击`chooseone`发起交互后，再点击`getflag`进行交互。

![](https://paper.tanyaodan.com/BUUCTF/TheChosenOne/4.png)

在[**Etherscan**](https://goerli.etherscan.io/tx/0x223683bbb656d68e51431935facfa8ba0a7951b7f6e9edb099e43016eb0d5f53)中可以找到本次交易，可以看到本次交易触发了`isSolved`事件，复制`Transaction Hash`，`nc`链接靶机选择`3`选项，输入`token`和`tx hash`即可得到`flag{Y0u_ar3_th3_ch00s3n_0n3}`。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ nc 124.221.212.109 10002
Who is the chosen one?
Get the flag after isSolved event is emitted！

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 3
[-] input your token: v4.local.BjOiqkzMdk1cl8-0PjmXSp1rKdG3WoMmL47Rdi3H7bLnuDV2ZbxanylQBhm3kY_IcSsjuMzXVcxI0ajp_3KTETO0cwp35Cekb5gfEY-zu6LPj0Cw7BSCtrmeo0UlwcfBRRHRNqIA1kFCE9wu3HEdTg3628U4N2aWx-FJk4tJZMtQ3Q
[-] input tx hash that emitted isSolved event: 0x223683bbb656d68e51431935facfa8ba0a7951b7f6e9edb099e43016eb0d5f53
[+] flag: flag{Y0u_ar3_th3_ch00s3n_0n3}
```

------

