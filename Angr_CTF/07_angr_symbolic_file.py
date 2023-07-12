import angr
import claripy

path_to_binary = './07_angr_symbolic_file'
project = angr.Project(path_to_binary, auto_load_libs=False)
start_address = 0x80488D6
initial_state = project.factory.blank_state(
    addr = start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)
filename = 'OJKSQYDP.txt'
file_size_bytes = 64
password = claripy.BVS('password', file_size_bytes*8)
passwd_file = angr.storage.SimFile(filename, content=password, size=file_size_bytes)
initial_state.fs.insert(filename, passwd_file)
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.solver.eval(password, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: {}'.format(passwd))
else:
    raise Exception('Could not find the solution')