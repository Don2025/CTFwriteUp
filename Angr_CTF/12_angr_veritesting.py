import angr

path_to_binary = './12_angr_veritesting'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
simulation = project.factory.simgr(initial_state, veritesting=True)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()
    print('[+] Congratulations! Solution is: %s' % passwd)
else:
    raise Exception('Could not find the solution')