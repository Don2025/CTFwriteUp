from Crypto.PublicKey import RSA
from base64 import b64decode
from libnum import *

with open('pubkey1.pem', 'rb') as f:
    pubkey1 = RSA.import_key(f.read())

n1 = pubkey1.n
e1 = pubkey1.e
# n1 = 14853081277902411240991719582265437298941606850989432655928075747449227799832389574251190347654658701773951599098366248661597113015221566041305501996451638624389417055956926238595947885740084994809382932733556986107653499144588614105694518150594105711438983069306254763078820574239989253573144558449346681620784979079971559976102366527270867527423001083169127402157598183442923364480383742653117285643026319914244072975557200353546060352744263637867557162046429886176035616570590229646013789737629785488326501654202429466891022723268768841320111152381619260637023031430545168618446134188815113100443559425057634959299
# e1 = 2333 
with open('pubkey2.pem', 'rb') as f:
    pubkey2 = RSA.import_key(f.read())

n2 = pubkey2.n
e2 = pubkey2.e
# n2 = 14853081277902411240991719582265437298941606850989432655928075747449227799832389574251190347654658701773951599098366248661597113015221566041305501996451638624389417055956926238595947885740084994809382932733556986107653499144588614105694518150594105711438983069306254763078820574239989253573144558449346681620784979079971559976102366527270867527423001083169127402157598183442923364480383742653117285643026319914244072975557200353546060352744263637867557162046429886176035616570590229646013789737629785488326501654202429466891022723268768841320111152381619260637023031430545168618446134188815113100443559425057634959299
# e2 = 23333
with open('myflag1', 'rb') as f:
    c1 = s2n(b64decode(f.read()))

with open('myflag2', 'rb') as f:
    c2 = s2n(b64decode(f.read()))

s = xgcd(e1, e2) #扩展欧几里得算法
m1 = pow(c1, s[0], n1)
m2 = pow(c2, s[1], n2)
m = (m1*m2)%n1
flag = n2s(m).decode()
print(flag)   # flag{23re_SDxF_y78hu_5rFgS}