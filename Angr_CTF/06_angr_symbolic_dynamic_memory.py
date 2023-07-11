import angr
import claripy

path_to_binary = './06_angr_symbolic_dynamic_memory'
project = angr.Project(path_to_binary, auto_load_libs=False)
start_address = 0x8048699
initial_state = project.factory.blank_state(
    addr = start_address,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
)
# The binary is calling scanf("%8s %8s").
password0 = claripy.BVS('p0', 64)
password1 = claripy.BVS('p1', 64)
fake_heap_address0 = 0xffff666
pointer_to_malloc_memory_address0 = 0xABCC8A4
initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
initial_state.memory.store(fake_heap_address0, password0)
fake_heap_address1 = 0xffff676
pointer_to_malloc_memory_address1 = 0xABCC8AC
initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)
initial_state.memory.store(fake_heap_address1, password1)
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd0 = solution_state.solver.eval(password0, cast_to=bytes).decode()
    passwd1 = solution_state.solver.eval(password1, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: {} {}'.format(passwd0, passwd1))
else:
    raise Exception('Could not find the solution')