import random
import time
#from secret import flag

def LC(key, x, times, flags):
    (k1, k2) = key
    xn = []
    xn.append(x)
    if flags:
        xn.append(1 - 2 * xn[0]**2)
    else:
        xn.append(k2 * xn[0]**3 + (1 - k2)*xn[0])
    for i in range(times):
        assert xn[i]>=-1 and xn[i]<=1 and xn[i+1]>=-1 and xn[i+1]<=1
        if flags:
            xn.append((1 - 2 * xn[i]**2)*(k1 * xn[i+1]**3 + (1 - k1)*xn[i+1]))
        else:
            xn.append((k2 * xn[i]**3 + (1 - k2)*xn[i])*(1 - 2 * xn[i+1]**2))
    return xn[times + 1]

def init(): 
    sum, r, k = 0, 1, []
    #k1 = random.uniform(3.2, 4) 
    #k2 = random.uniform(3.2, 4)
    k1, k2 = 3.967139695598587, 3.7926025078694305                                           
    k = [107, 99, 55, 198, 210, 56, 137, 44, 127, 25, 150, 113, 75, 215, 187, 132]           

    for i in range(16): 
        #k.append(random.randint(1,256)) 
        sum += k[i]
        r ^= k[i]  
    a_1 = (sum/256) % 1 
    timea1 = 3 + int(1000 * a_1) % 30
    b_1 = (r/256)
    timeb1 = 3 + int(1000 * b_1) % 30
    xc_1 = a_1 * b_1
    yc_1 = (a_1 + b_1) % 1
    print('k1, k2 = %r, %r'%(k1, k2))
    print('k = %r'%k)
    return (k1, k2), (a_1, timea1, b_1, timeb1, xc_1, yc_1)

def decrypt(key, data):
                                            
    #k = [107, 99, 55, 198, 210, 56, 137, 44, 127, 25, 150, 113, 75, 215, 187, 132]           
    c = [23, 84, 105, 111, 230, 105, 97, 50, 58, 61, 25, 97, 57, 21, 175, 77, 102, 138, 120, 17, 66, 172, 52, 178, 101, 221, 109, 126, 71, 149, 63, 32, 56, 6, 134, 255, 110, 57, 15, 20, 116]

    (k1, k2)=key
    (a_1, timea1, b_1, timeb1, xc_1, yc_1) = data
    #flag = list(flag)
    
    miu, omiga = [], []
    ta = timea1
    tb = timeb1
    m=''
    for tmp in c:
        #mi = ord(tmp)
        miu.append(LC(key, a_1, ta, 1))
        omiga.append(LC(key, b_1, tb, 0))
        #c.append(((int(miu[-1] * 1000) + int(omiga[-1] * 1000)) ^ mi) % 256)
        
        m+=(chr(tmp^((int(miu[-1] * 1000) + int(omiga[-1] * 1000)))%256))
        delta = tmp/256
        for i in range(3):
            y = (yc_1 + delta) % 1
            y = k1 * y**3 + (1 - k1) * y
            x = xc_1
            x = k2 * x**3 + (1 - k2) * x
        ta = 3 + int(1000 * x) % 30
        tb = 3 + int(1000 * y) % 30
    print('m= %r'%(m))
    return m

if __name__=="__main__":
    # print(flag)
    (key, data)=init()
    c = decrypt(key, data)

'''
k1, k2 = 3.967139695598587, 3.7926025078694305
k = [107, 99, 55, 198, 210, 56, 137, 44, 127, 25, 150, 113, 75, 215, 187, 132]
m= 'flag{ii24nji9-8ckkpil1-5hiev3n6-1u24g07m}'
'''
