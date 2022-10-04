encoded = "GjN3G$B3de58ym&7wQh9dgVNGQhfG2hndsGjlOyEdaxRFY"
alphabet = "c5PKAQmgI&qSdyDZYCbOV2seXGloLwtFW3f9n7j481UMHBp6vNETRJa$rxuz0hik"
bits = ''
for i in encoded:
    bits += bin(alphabet.index(i))[2:].rjust(6, '0')
print(bits)
flag = ''
for i in range(0, len(bits), 8):
    flag += chr(int(bits[i:i+8], 2))
print(flag)