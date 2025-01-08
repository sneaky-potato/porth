#!/usr/bin/env python3

import sys
import subprocess

iota_counter = 0


def iota(reset=False):
    global iota_counter
    if reset:
        iota_counter = 0
    result = iota_counter
    iota_counter += 1
    return result


OP_PUSH = iota(True)
OP_PLUS = iota()
OP_MINUS = iota()
OP_EQUAL = iota()
OP_IF = iota()
OP_ELSE = iota()
OP_END = iota()
OP_DUP = iota()
OP_SWAP = iota()
OP_DROP = iota()
OP_OVER = iota()
OP_SHL = iota()
OP_SHR = iota()
OP_OR = iota()
OP_AND = iota()
OP_GT = iota()
OP_LT = iota()
OP_WHILE = iota()
OP_DO = iota()
OP_MEM = iota()
OP_LOAD = iota()
OP_STORE = iota()
OP_DUMP = iota()
OP_SYSCALL3 = iota()
COUNT_OPS = iota()


MEM_CAPACITY = 640_000


def push(x):
    return (OP_PUSH, x)


def plus():
    return (OP_PLUS, )


def minus():
    return (OP_MINUS, )


def equal():
    return (OP_EQUAL, )


def iff():
    return (OP_IF, )


def elsef():
    return (OP_ELSE, )


def end():
    return (OP_END, )


def dup():
    return (OP_DUP, )


def swap():
    return (OP_SWAP, )


def drop():
    return (OP_DROP, )


def over():
    return (OP_OVER, )


def shl():
    return (OP_SHL, )


def shr():
    return (OP_SHR, )


def orf():
    return (OP_OR, )


def andf():
    return (OP_AND, )


def lt():
    return (OP_LT, )


def gt():
    return (OP_GT, )


def whilef():
    return (OP_WHILE, )


def dof():
    return (OP_DO, )


def mem():
    return (OP_MEM, )


def load():
    return (OP_LOAD, )


def store():
    return (OP_STORE, )


def dump():
    return (OP_DUMP, )


def syscall3():
    return (OP_SYSCALL3, )


def simulate_program(program):
    stack = []
    mem = bytearray(MEM_CAPACITY)
    ip = 0
    while ip < len(program):
        assert COUNT_OPS == 16, "Exhastive counting in simulation"
        op = program[ip]
        if op[0] == OP_PUSH:
            stack.append(op[1])
            ip += 1
        elif op[0] == OP_PLUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(a + b)
            ip += 1
        elif op[0] == OP_MINUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(b - a)
            ip += 1
        elif op[0] == OP_EQUAL:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a == b))
            ip += 1
        elif op[0] == OP_IF:
            a = stack.pop()
            if a == 0:
                assert len(op) >= 2, "`if` instruction does not have reference to end of its block, please use end after if"
                ip = op[1]
            else:
                ip += 1
        elif op[0] == OP_ELSE:
            assert len(op) >= 2, "`else` instruction does not have reference to end of its block, please use end after if"
            # jump to end of block
            ip = op[1]
        elif op[0] == OP_END:
            assert len(op) >= 2, "`end` instruction does not have reference to next instruction"
            ip = op[1]
        elif op[0] == OP_DUP:
            a = stack.pop()
            stack.append(a)
            stack.append(a)
            ip += 1
        elif op[0] == OP_GT:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a < b))
            ip += 1
        elif op[0] == OP_WHILE:
            ip += 1
        elif op[0] == OP_DO:
            a = stack.pop()
            if a == 0:
                assert len(op) >= 2, "`do` instruction does not have reference to next instruction"
                ip = op[1]
            else:
                ip += 1
        elif op[0] == OP_MEM:
            stack.append(0)
            ip += 1
        elif op[0] == OP_LOAD:
            addr = stack.pop()
            byte = mem[addr]
            stack.append(byte)
            ip += 1
        elif op[0] == OP_STORE:
            value = stack.pop()
            addr = stack.pop()
            mem[addr] = value % 0xFF
            ip += 1
        elif op[0] == OP_DUMP:
            a = stack.pop()
            print(a)
            ip += 1
        elif op[0] == OP_SYSCALL3:
            syscall_number = stack.pop()
            arg1 = stack.pop()
            arg2 = stack.pop()
            arg3 = stack.pop()
            if syscall_number == 1:
                fd = arg1
                buf = arg2
                count = arg3
                s = mem[buf:buf+count].decode('utf-8')
                if fd == 1:
                    print(s, end='')
                elif fd == 2:
                    print(s, end='', file=sys.stderr)
                else:
                    assert False, "unknown file descriptor %d" % fd
            else:
                assert False, "unknown syscall number %d" % syscall_number
            ip += 1
        else:
            assert False, "Unreachable"


def compile_program(program, out_file_path):
    with open(out_file_path, "w") as out:
        out.write("segment .text\n")
        out.write("dump:\n")
        out.write("    push    rbp\n")
        out.write("    mov     rbp, rsp\n")
        out.write("    sub     rsp, 64\n")
        out.write("    mov     QWORD [rbp-56], rdi\n")
        out.write("    mov     QWORD [rbp-8], 1\n")
        out.write("    mov     eax, 32\n")
        out.write("    sub     rax, QWORD [rbp-8]\n")
        out.write("    mov     BYTE [rbp-48+rax], 10\n")
        out.write(".L2:\n")
        out.write("    mov     rcx, QWORD [rbp-56]\n")
        # movabs
        out.write("    mov     rdx, -3689348814741910323\n")
        out.write("    mov     rax, rcx\n")
        out.write("    mul     rdx\n")
        out.write("    shr     rdx, 3\n")
        out.write("    mov     rax, rdx\n")
        out.write("    sal     rax, 2\n")
        out.write("    add     rax, rdx\n")
        out.write("    add     rax, rax\n")
        out.write("    sub     rcx, rax\n")
        out.write("    mov     rdx, rcx\n")
        out.write("    mov     eax, edx\n")
        out.write("    lea     edx, [rax+48]\n")
        out.write("    mov     eax, 31\n")
        out.write("    sub     rax, QWORD [rbp-8]\n")
        out.write("    mov     BYTE [rbp-48+rax], dl\n")
        out.write("    add     QWORD [rbp-8], 1\n")
        out.write("    mov     rax, QWORD [rbp-56]\n")
        # movabs
        out.write("    mov     rdx, -3689348814741910323\n")
        out.write("    mul     rdx\n")
        out.write("    mov     rax, rdx\n")
        out.write("    shr     rax, 3\n")
        out.write("    mov     QWORD [rbp-56], rax\n")
        out.write("    cmp     QWORD [rbp-56], 0\n")
        out.write("    jne     .L2\n")
        out.write("    mov     eax, 32\n")
        out.write("    sub     rax, QWORD [rbp-8]\n")
        out.write("    lea     rdx, [rbp-48]\n")
        out.write("    lea     rcx, [rdx+rax]\n")
        out.write("    mov     rax, QWORD [rbp-8]\n")
        out.write("    mov     rdx, rax\n")
        out.write("    mov     rsi, rcx\n")
        out.write("    mov     edi, 1\n")
        # write
        out.write("    mov     rax, 1\n")
        out.write("    syscall\n")
        out.write("    nop\n")
        out.write("    leave\n")
        out.write("    ret\n")

        out.write("global _start\n")
        out.write("_start:\n")
        for ip in range(len(program)):
            out.write("addr_%d:\n" % ip)
            op = program[ip]
            assert COUNT_OPS == 24, "Exhaustive counting in compilation"
            if op[0] == OP_PUSH:
                out.write("    ;; -- push %d --\n" % op[1])
                out.write("    push %d\n" % op[1])
            elif op[0] == OP_PLUS:
                out.write("    ;; -- plus --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    add rax, rbx\n")
                out.write("    push rax\n")
            elif op[0] == OP_MINUS:
                out.write("    ;; -- minus --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    sub rbx, rax\n")
                out.write("    push rbx\n")
            elif op[0] == OP_EQUAL:
                out.write("    ;; -- equal --\n")
                out.write("    mov rcx, 0\n")
                out.write("    mov rdx, 1\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    cmp rbx, rax\n")
                out.write("    cmove rcx, rdx\n")
                out.write("    push rcx\n")
            elif op[0] == OP_IF:
                out.write("    ;; -- if --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert len(op) >= 2, "`if` instruction does not have reference to end of its block, please use end after if"
                out.write("    jz addr_%d\n" % op[1])
            elif op[0] == OP_ELSE:
                out.write("    ;; -- else --\n")
                assert len(op) >= 2, "`else` instruction does not have reference to end of its block, please use end after if"
                out.write("    jmp addr_%d\n" % op[1])
                # label for else body
                # out.write("addr_%d:\n" % (ip + 1))
            elif op[0] == OP_END:
                out.write("    ;; -- end --\n")
                assert len(op) >= 2, "`end` instruction does not have reference to next instruction"
                if ip + 1 != op[1]:
                    out.write("    jmp addr_%d\n" % op[1])
            elif op[0] == OP_DUP:
                out.write("    ;; -- dup --\n")
                out.write("    pop rax\n")
                out.write("    push rax\n")
                out.write("    push rax\n")
            elif op[0] == OP_DROP:
                out.write("    ;; -- drop --\n")
                out.write("    pop rax\n")
            elif op[0] == OP_OVER:
                out.write("    ;; -- over --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    push rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")

            elif op[0] == OP_SHR:
                out.write("    ;; -- shr --\n")
                out.write("    pop rcx\n")
                out.write("    pop rbx\n")
                out.write("    shr rbx, cl\n")
                out.write("    push rbx\n")
            elif op[0] == OP_SHL:
                out.write("    ;; -- shl --\n")
                out.write("    pop rcx\n")
                out.write("    pop rbx\n")
                out.write("    shl rbx, cl\n")
                out.write("    push rbx\n")
            elif op[0] == OP_OR:
                out.write("    ;; -- or --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    or rbx, rax\n")
                out.write("    push rbx\n")
            elif op[0] == OP_AND:
                out.write("    ;; -- and --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    and rbx, rax\n")
                out.write("    push rbx\n")
            elif op[0] == OP_SWAP:
                out.write("    ;; -- swap --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
            elif op[0] == OP_GT:
                out.write("    ;; -- gt --\n")
                out.write("    mov rcx, 0\n")
                out.write("    mov rdx, 1\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    cmp rax, rbx\n")
                out.write("    cmovg rcx, rdx\n")
                out.write("    push rcx\n")
            elif op[0] == OP_LT:
                out.write("    ;; -- lt --\n")
                out.write("    mov rcx, 0\n")
                out.write("    mov rdx, 1\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    cmp rax, rbx\n")
                out.write("    cmovl rcx, rdx\n")
                out.write("    push rcx\n")
            elif op[0] == OP_GT:
                out.write("    ;; -- gt --\n")
                out.write("    mov rcx, 0\n")
                out.write("    mov rdx, 1\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    cmp rax, rbx\n")
                out.write("    cmovg rcx, rdx\n")
                out.write("    push rcx\n")
            elif op[0] == OP_WHILE:
                out.write("    ;; -- while --\n")
            elif op[0] == OP_DO:
                out.write("    ;; -- do --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert len(op) >= 2, "`do` instruction does not have reference to end of its block, please use end after if"
                out.write("    jz addr_%d\n" % op[1])
            elif op[0] == OP_MEM:
                out.write("    ;; -- mem --\n")
                out.write("    push mem\n")
            elif op[0] == OP_LOAD:
                out.write("    ;; -- load --\n")
                out.write("    pop rax\n")
                out.write("    xor rbx, rbx\n")
                out.write("    mov bl, [rax]\n")
                out.write("    push rbx\n")
            elif op[0] == OP_STORE:
                out.write("    ;; -- store --\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    mov [rax], bl\n")
            elif op[0] == OP_DUMP:
                out.write("    ;; -- dump --\n")
                out.write("    pop rdi\n")
                out.write("    call dump\n")
            elif op[0] == OP_SYSCALL3:
                out.write("    ;; -- syscall --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    syscall\n")
            else:
                assert False, "Unreachable"
        out.write("addr_%d:\n" % len(program))
        out.write("    mov rax, 60\n")
        out.write("    mov rdi, 0\n")
        out.write("    syscall\n")
        out.write("segment .bss\n")
        out.write("mem resb %d\n" % MEM_CAPACITY)


def usage(program):
    print("Usage: %s <OPTION> [ARGS]" % program)
    print("OPTIONS:")
    print("    sim <file>        Simulate program")
    print("    com <file>        Compile program")
    print("        SUBOPTIONS:")
    print("            -r        run the program after successful compilation")
    print("    help              Print this help to stdout")


def call_cmd(cmd):
    print(cmd)
    subprocess.call(cmd)


def uncons(xs):
    return (xs[0], xs[1:])


def parse_token_as_op(token):
    (file_path, row, col, word) = token
    assert COUNT_OPS == 24, "Exhaustive handling in parse_token_as_op"
    if word == '+':
        return plus()
    elif word == '-':
        return minus()
    elif word == '=':
        return equal()
    elif word == 'if':
        return iff()
    elif word == 'else':
        return elsef()
    elif word == 'end':
        return end()
    elif word == 'dup':
        return dup()
    elif word == 'swap':
        return swap()
    elif word == 'drop':
        return drop()
    elif word == 'over':
        return over()
    elif word == 'shl':
        return shl()
    elif word == 'shr':
        return shr()
    elif word == 'or':
        return orf()
    elif word == 'and':
        return andf()
    elif word == '<':
        return lt()
    elif word == '>':
        return gt()
    elif word == 'while':
        return whilef()
    elif word == 'do':
        return dof()
    elif word == 'mem':
        return mem()
    elif word == ',':
        return load()
    elif word == '.':
        return store()
    elif word == 'dump':
        return dump()
    elif word == 'syscall3':
        return syscall3()
    else:
        try:
            return push(int(word))
        except ValueError as err:
            print("%s:%d:%d: %s", file_path, row, col, err)
            exit(1)


def crossreference_blocks(program):
    stack = []
    for ip in range(len(program)):
        op = program[ip]
        assert COUNT_OPS == 24, "Exhaustive handling of ops in crossreference_blocks"
        if op[0] == OP_IF:
            stack.append(ip)
        elif op[0] == OP_ELSE:
            if_ip = stack.pop()
            assert program[if_ip][0] == OP_IF, "else can only be used inside if blocks"
            # ip + 1 so that it doesn't jump to else but rather body of else
            program[if_ip] = (OP_IF, ip + 1)
            stack.append(ip)
        elif op[0] == OP_END:
            block_ip = stack.pop()
            if program[block_ip][0] == OP_IF or program[block_ip][0] == OP_ELSE:
                program[block_ip] = (program[block_ip][0], ip)
                program[ip] = (OP_END, ip + 1)
            elif program[block_ip][0] == OP_DO:
                assert len(program[block_ip]) >= 2, "end does not have address to next instruction"
                # reference to address stored in `do` (which is address of while)
                program[ip] = (OP_END, program[block_ip][1])
                # store address of after `end` block to `do` operation
                program[block_ip] = (OP_DO, ip + 1)
            else:
                assert False, "end can only close `if` `else` `do` blocks for now"
        elif op[0] == OP_WHILE:
            stack.append(ip)
        elif op[0] == OP_DO:
            while_ip = stack.pop()
            program[ip] = (OP_DO, while_ip)
            stack.append(ip)

    return program


def find_col(line, col, predicate):
    while col < len(line) and not predicate(line[col]):
        col += 1
    return col


def lex_line(line):
    col = find_col(line, 0, lambda x: not x.isspace())
    while col < len(line):
        col_end = find_col(line, col, lambda x: x.isspace())
        yield (col, line[col:col_end])
        col = find_col(line, col_end, lambda x: not x.isspace())


def lex_file(file_path):
    with open(file_path, "r") as f:
        return [
            (file_path, row, col, token)
            for (row, line) in enumerate(f.readlines())
            for (col, token) in lex_line(line.split("//")[0])
        ]


def load_program_from_file(file_path):
    return crossreference_blocks([
        parse_token_as_op(token) for token in lex_file(file_path)
    ])


if __name__ == "__main__":
    argv = sys.argv
    assert len(argv) >= 1
    (program_name, argv) = uncons(argv)
    if len(argv) < 1:
        usage(program_name)
        print("ERROR: no option is provided")
        exit(1)
    (option, argv) = uncons(argv)
    if option == "sim":
        if len(argv) < 1:
            usage(program_name)
            print("ERROR: no input file is provided for simulation")
            exit(1)
        (program_path, argv) = uncons(argv)
        program = load_program_from_file(program_path)
        simulate_program(program)
    elif option == "com":
        flag = None
        if len(argv) < 1:
            usage(program_name)
            print("ERROR: no input file is provided for compilation")
            exit(1)
        if len(argv) == 1:
            (program_path, argv) = uncons(argv)
        else:
            (flag, argv) = uncons(argv)
            if flag.startswith('-') and flag != '-r':
                usage(program_name)
                print("ERROR: unknown flag: %s" % flag)
                exit(1)
            (program_path, argv) = uncons(argv)

        program = load_program_from_file(program_path)
        compile_program(program, "output.asm")
        call_cmd(["nasm", "-felf64", "output.asm"])
        call_cmd(["ld", "-o", "output", "output.o"])
        if flag is not None:
            call_cmd(["./output"])
    elif option == "help":
        usage(program_name)
        exit(1)
    else:
        usage(program_name)
        print("ERROR: unknown option %s" % (option))
        exit(0)
