all:
	@gcc -o frank frank.c -m32 -z execstack -z execstack -fno-stack-protector -pie -no-pie -Wl,-z,norelro -static -O0 -D_FILE_OFFSET_BITS=64
