import angr
import claripy

path_to_binary = './08_angr_constraints'
project = angr.Project(path_to_binary, auto_load_libs=False)
start_address = 0x8048625
initial_state = project.factory.blank_state(
    addr = start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)
passwd_bytes = 0x10
char_size_bits = 0x8
password = claripy.BVS('password', passwd_bytes*char_size_bits)
buffer_address = 0x804A050
initial_state.memory.store(buffer_address, password)
simulation = project.factory.simgr(initial_state)
check_address = 0x8048565  # check_equals_AUPDNNPROEZRJWKB()
constrained_value = b'AUPDNNPROEZRJWKB' # If the value is equal to "AUPDNNPROEZRJWKB", WARNING: BVV value is being coerced from a unicode string, encoding as utf-8.
simulation.explore(find=check_address)
if simulation.found:
    solution_state = simulation.found[0]
    buffer_content = solution_state.memory.load(buffer_address, passwd_bytes)
    solution_state.solver.add(buffer_content == constrained_value)
    passwd = solution_state.solver.eval(password, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: {}'.format(passwd))
else:
    raise Exception('Could not find the solution')