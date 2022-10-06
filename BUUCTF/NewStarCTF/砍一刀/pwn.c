#include<stdio.h>
#include<string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

int init();
void game();
void getcard();
void getdiamond();
void success();
int cipher();

int diamond=5;

int init(){
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

void game(){
    float money=0;
    int key=0;
    printf("NewstarCTF送你现金红包啦!\n\n");
    sleep(1.5);
    printf("恭喜你成为幸运星，最高可提现100元红包！\n\n");
    sleep(1.5);
    printf("恭喜你获得一张百元现金卡，使用可以加速领红包！\n\n");
    printf("按回车键使用现金卡……\n\n");
    getchar();
    sleep(1.5);
    printf("成功使用百元现金卡，获得50元现金！\n\n");
    money+=50;
    sleep(1.5);
    printf("今日难度降低，送你30元现金！\n\n");
    money+=30;
    sleep(1.5);
    printf("第一次参加活动，再送你10元现金！\n\n");
    money+=10;
    sleep(1.5);
    printf("感谢你对NewstarCTF的大力支持，再送你9元现金！\n\n");
    money+=9;
    sleep(1.5);
    printf("真棒！仅剩1%%提现红包！\n\n");
    sleep(1.5);
    printf("还有66人正在提现红包，你的提现进度第一，将最先提现！\n\n");
    sleep(1.5);
    printf("回车一下，再砍一刀\n\n");
    getchar();
    sleep(1.5);
    printf("恭喜获得0.45元现金！\n\n");
    sleep(1.5);
    printf("送你现金翻倍卡，更快提现！\n\n");
    sleep(1.5);
    printf("翻倍生效中……成功翻2倍！\n0.45元----->0.9元\n\n");
    money+=0.9;
    sleep(1.5);
    printf("距离提现只有一步之遥啦，输入口令666领取红包！\n");
    cipher();
    printf("\n口令正确，送你0.05元现金！\n\n");
    sleep(1.5);
    printf("翻倍生效中……成功翻2倍！\n0.05元----->0.1元\n\n");
    money+=0.1;
    sleep(1.5);
    printf("恭喜你集齐100元红包！\n\n");
    sleep(1.5);
    printf("赶紧分享给好友庆祝一下吧！\n\n");
    sleep(1.5);
    printf("按回车键分享给好友~\n\n");
    getchar();
    printf("分享成功！\n\n");
    getcard();
}

void getcard(){
    srand((unsigned int)time(NULL));
    int luck=0;
    int coin=0;
    printf("有好友帮你砍一刀，成功获得500金币！\n");
    coin+=500;
    sleep(1.5);
    printf("有好友帮你砍一刀，成功获得400金币！\n");
    coin+=400;
    sleep(1.5);
    printf("=======================================\n");
    printf("集齐1000金币，兑换提现卡，马上提现红包！\n");
    printf("=======================================\n");
    sleep(1.5);
    printf("马上就能兑换提现卡啦，赶紧邀请好友帮你砍一刀吧！\n");
    printf("当前金币：%d个\n\n",coin);
    while(1){
        printf("按回车键邀请好友砍一刀，领取金币~\n");
        getchar();
        sleep(1);
        printf("有好友帮你砍一刀啦!");
        if(coin==999){
            luck=rand()%101;
            if((luck%10)==0){
                printf("==========================================================\n");
                printf("恭喜你触发隐藏福利，集齐10颗钻石兑换1金币，加速兑换提现卡！\n");
                printf("==========================================================\n");
                getdiamond();
            }
            else{
                printf("很遗憾本次未获得金币……\n");
            }
        }
        else{
            if(coin>=900&&coin<990){
                printf("成功获得10金币……\n");
                coin+=10;
            }
            else{
                printf("成功获得1金币……\n");
                coin+=1;
            }
        }
        printf("当前金币：%d个\n\n",coin);
    }
}   

void getdiamond(){
    int luck=0;
    char password[100];
    printf("======================\n");
    printf("你真幸运，送你5颗钻石！\n");
    printf("======================\n");
    sleep(1.5);
    printf("马上就能集齐钻石啦，赶紧邀请好友帮你砍一刀吧！\n\n");
    while(1){
        if(diamond==10){
            success();
        }
        else{
            printf("按回车键邀请好友砍一刀，领取钻石~\n");
            getchar();
            sleep(1);
            printf("有好友帮你砍一刀啦!");
            if(diamond==9){
                luck=rand()%101;
                if((luck%10)==0){
                    printf("===============================================================\n");
                    printf("你意外触发了隐藏福利！离成功就差一点点啦，输入神秘口令领取钻石！\n");
                    printf("===============================================================\n");
                    sleep(1);
                    printf("输入口令==>");
                    init();
                    read(0,password,101);
                    printf(password);
                }
                else{
                    printf("很遗憾本次未获得钻石……\n");
                }
            }
            else{
                printf("成功获得1钻石！\n");
                diamond+=1;
            }
        }
        printf("当前钻石：%d颗\n\n",diamond);
    }
}

void success(){
    printf("===================\n");
    printf("恭喜你集齐10颗钻石！\n");
    printf("===================\n");
    sleep(1.5);
    printf("按回车键兑换金币！\n\n");
    sleep(1.5);
    printf("金币兑换成功！\n\n");
    sleep(1.5);
    printf("===================\n");
    printf("恭喜你集齐1000金币！\n");
    printf("===================\n");
    sleep(1.5);
    printf("按回车键兑换提现卡！\n\n");
    sleep(1.5);
    printf("提现卡兑换成功！\n\n");
    sleep(1.5);
    printf("正在使用提现卡");
    sleep(1.5);
    printf("...");
    sleep(1.5);
    printf("...");
    sleep(1.5);
    printf("...\n");
    sleep(1.5);
    printf("恭喜你成功提现红包！正在飞速转账~");
    sleep(1.5);
    printf("...");
    sleep(1.5);
    printf("...\n");
    printf("转账成功！\n");
    system("/bin/sh");
}

int cipher()
{
    printf("==>");
    int n, judge;
    scanf("%d", &n);
    judge = getchar();
    while(n != 666)
    {
        fflush(stdin);
        printf("口令错误，请重新输入\n==>");
        scanf("%d", &n);
        judge = getchar();
    }
    return n;
}

int main(){
    init();
    game();
}
