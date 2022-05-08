#include <stdio.h>
#include <string.h>
using namespace std;

const char * base64char = "/abcdefghIJKLMNOPQRSTUVWXYZABCDEFGijklmnopqrstuvwxyz0123456789+";
const char padding_char = '=';

int base64_encode(const unsigned char * sourcedata, char * base64) {
    int i=0, j=0;
    unsigned char trans_index=0;   // 索引是8位，但是高两位都为0

    const int datalength = strlen((const char*)sourcedata);

    for (; i < datalength; i += 3) {    // 每三个一组，进行编码 要编码的数字的第一个
    
        trans_index = ((sourcedata[i] >> 2) & 0x3f);
        base64[j++] = base64char[(int)trans_index];

        // 第二个
        trans_index = ((sourcedata[i] << 4) & 0x30);

        if (i + 1 < datalength){
            trans_index |= ((sourcedata[i + 1] >> 4) & 0x0f);
            base64[j++] = base64char[(int)trans_index];
        }else{
            base64[j++] = base64char[(int)trans_index];
            base64[j++] = padding_char;
            base64[j++] = padding_char;
            break;                              // 超出总长度，可以直接break
        }

        // 第三个
        trans_index = ((sourcedata[i + 1] << 2) & 0x3c);
        if (i + 2 < datalength) {                           // 有的话需要编码2个
            trans_index |= ((sourcedata[i + 2] >> 6) & 0x03);
            base64[j++] = base64char[(int)trans_index];
 
            trans_index = sourcedata[i + 2] & 0x3f;
            base64[j++] = base64char[(int)trans_index];
        }else {
            base64[j++] = base64char[(int)trans_index];
            base64[j++] = padding_char;
            break;
        }
    }

    base64[j] = '\0'; 

    return 0;
}
 
int num_strchr(const char *str, char c) {
    const char *pindex = strchr(str, c);
    if (NULL == pindex) {
        return -1;
    }
    return pindex - str;
}
 
int base64_decode(const char * base64, unsigned char * dedata) {
    int i = 0, j=0;
    int trans[4] = {0,0,0,0};
 
    for (;base64[i]!='\0';i+=4) { // 每四个一组，译码成三个字符
 
        trans[0] = num_strchr(base64char, base64[i]);
        trans[1] = num_strchr(base64char, base64[i+1]);

        dedata[j++] = ((trans[0] << 2) & 0xfc) | ((trans[1]>>4) & 0x03);

        if (base64[i+2] == '='){
            continue;
        }else{
            trans[2] = num_strchr(base64char, base64[i + 2]);
        }

        dedata[j++] = ((trans[1] << 4) & 0xf0) | ((trans[2] >> 2) & 0x0f);

        if (base64[i + 3] == '='){
            continue;
        }else{
            trans[3] = num_strchr(base64char, base64[i + 3]);
        }

        dedata[j++] = ((trans[2] << 6) & 0xc0) | (trans[3] & 0x3f);
    }
    dedata[j] = '\0';
    return 0;
}

int main() {
    char base641[128]="YmxGY3s3MnMnYjd3Y2X5XWM5YfpoXWQkNSMlMzMnYjl9=";
    printf("%s\n",base641);
    char dedata[128];
    int b=strlen(base641);
    printf("%d\n",b);
    base64_decode(base641, (unsigned char*)dedata);
    int v3=0;
    int v2=38;
    printf("%s\n", dedata);
    return 0;
}