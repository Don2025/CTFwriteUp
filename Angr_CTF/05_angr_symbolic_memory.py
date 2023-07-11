import angr
import claripy

path_to_binary = './05_angr_symbolic_memory'
project = angr.Project(path_to_binary, auto_load_libs=False)
start_address = 0x8048601
initial_state = project.factory.blank_state(
    addr = start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)
# The binary is calling scanf("%8s %8s %8s %8s").
password0_address = 0xA1BA1C0
password0 = claripy.BVS('p0', 64)
initial_state.memory.store(password0_address, password0)
password1 = claripy.BVS('p1', 64)
initial_state.memory.store(password0_address+0x8, password1)
password2 = claripy.BVS('p2', 64)
initial_state.memory.store(password0_address+0x10, password2)
password3 = claripy.BVS('p3', 64)
initial_state.memory.store(password0_address+0x18, password3)
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd0 = solution_state.solver.eval(password0, cast_to=bytes).decode()
    passwd1 = solution_state.solver.eval(password1, cast_to=bytes).decode()
    passwd2 = solution_state.solver.eval(password2, cast_to=bytes).decode()
    passwd3 = solution_state.solver.eval(password3, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: {} {} {} {}'.format(passwd0, passwd1, passwd2, passwd3))
else:
    raise Exception('Could not find the solution')