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

在[**Etherscan**](https://etherscan.io)中查找对应的交易，可以看到生成合约的地址。

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



在[**Etherscan**](https://etherscan.io)中可以查找对应的交易，`Click to see More`可以看到`setGreeting(string _greeting)`函数已经被触发啦。

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

