msvc:
	cl /nologo /DTEST /O2 /Os maru.c
gnu:	
	gcc -DTEST -O2 -Os maru.c -omaru
clang:
	clang -DTEST -O2 -Os maru.c -omaru	