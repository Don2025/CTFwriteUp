v5 = [100, 121, 110, 118, 70, 85, 123, 109, 64, 94, 109, 99, 116, 81, 109, 86, 83, 126, 119, 101, 110, 114]
fibon = [2, 3]
# 补充计算fibon
for i in range(20):
    fibon.append(fibon[i] + fibon[i+1])
 
flag = ''
for i in range(22):
    base = v5[i]-64-fibon[i]-i  # 尝试得到变形的flag值，该值与正确flag值相差n个64
    while base < 64:  # 断言flag ASCII大于等于64
        base += 64
    flag += chr(base)

print(flag)   # bugku{So_Ez_Fibon@cci}