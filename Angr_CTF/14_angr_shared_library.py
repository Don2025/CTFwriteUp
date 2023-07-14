import angr
import claripy

path_to_binary = './lib14_angr_shared_library.so'
base_address = 0x8048000
project = angr.Project(path_to_binary, load_options={
    'main_opts': {
        'base_addr': base_address
    }
})
buffer_pointer = claripy.BVV(0x3000000, 32)
validate_address = base_address + 0x6d7
initial_state = project.factory.call_state(
    validate_address, buffer_pointer, claripy.BVV(8, 32),
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
password = claripy.BVS('password', 64)
initial_state.memory.store(buffer_pointer, password)
simulation = project.factory.simgr(initial_state)
success_address = base_address + 0x783
simulation.explore(find=success_address)
if simulation.found:
    solution_state = simulation.found[0]
    solution_state.add_constraints(solution_state.regs.eax != 0)
    passwd = solution_state.solver.eval(password, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: %s' % passwd)
else:
    raise Exception('Could not find the solution')