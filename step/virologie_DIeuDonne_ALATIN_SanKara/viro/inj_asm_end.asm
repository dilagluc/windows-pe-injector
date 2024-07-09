public replicator
public __end_of_code

injected segment read execute
    replicator proc
    int 3
    int 3
    int 3

    replicator endp

    db "COUCOU", 0
    __end_of_code label QWORD
            dq 0

injected ends


public __end_decrypt
decrypt segment read execute
    db "COUCOU", 0
    __end_decrypt label QWORD
                dq 0
decrypt ends

END
