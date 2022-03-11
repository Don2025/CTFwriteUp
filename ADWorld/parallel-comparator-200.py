differences = [0, 9, -9, -1, 13, -13, -4, -11, -9, -1, -7, 6, -13, 13, 3, 9, -13, -11, 6, -7]
for i in range(26):
    first_letter = 97 + i
    flag = ''.join([chr(first_letter+differences[i]) for i in range(len(differences))])
    print(flag) # first_letter = 108, flag is lucky_hacker_you_are