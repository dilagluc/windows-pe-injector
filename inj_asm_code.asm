public payload

injected segment read execute

    payload proc

        nop
        _test:
        int 3
        nop

        _end:
    payload endp

injected ends

END
