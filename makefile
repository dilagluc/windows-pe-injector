all: injpe.exe

.c.obj:
	cl.exe $*.c /Ob3 /O1 /c

.asm.obj:
	ml64.exe $*.asm /c

injpe.exe: injpe.obj inj_asm_begin.obj libproc.obj inj_asm_end.obj
	link.exe injpe.obj inj_asm_begin.obj libproc.obj inj_asm_end.obj -out:injpe.exe

test: test.exe

test.exe:
	cl.exe main.c /DDEBUG /c
	cl.exe libproc.c /DDEBUG /Ob3 /c
	link.exe main.obj libproc.obj -out:test.exe

clean:
	del *.obj

fclean: clean
	del *.exe
	copy /y ..\mapviewfile.exe mapviewfile_test.exe

check: fclean injpe.exe
	injpe.exe mapviewfile_test.exe
