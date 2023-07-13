import angr
import claripy

path_to_binary = './09_angr_hooks'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
check_address = 0x80486B3  # check_equals_XYMKBKUHNIQYNQXE
skip_len_bytes = 5
@project.hook(check_address, length=skip_len_bytes)
def skip_check_equal(state):
    buffer_address = 0x804A054
    passwd_bytes = 0x10
    buffer_content = state.memory.load(buffer_address, passwd_bytes)
    constrained_value = b'XYMKBKUHNIQYNQXE'
    register_size_bits = 32
    state.regs.eax = claripy.If(
        buffer_content == constrained_value,
        claripy.BVV(1, register_size_bits),
        claripy.BVV(0, register_size_bits)
    )

simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()
    print('[+] Congratulations! Solution is: {}'.format(passwd))
else:
    raise Exception('Could not find the solution')