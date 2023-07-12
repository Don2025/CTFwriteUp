import angr

project = angr.Project('./02_angr_find_condition')
initial_state = project.factory.entry_state(add_options={
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
simulation = project.factory.simgr(initial_state)
# set expected function to judge whether the output is succeessful according to the state.
# state.posix is the api for posix, and dumps(file discription number) will get the bytes for the pointed file. sys.stdout.fileno() is the stdout file discription number. we can replace it by 1.
# set expected function to judge whether the output is succeessful according to the state.
def is_successful(state):
    return b'Good Job' in state.posix.dumps(1)
# is_successful = lambda state: b'Good Job' in state.posix.dumps(1)
# set unexpected function
def should_abort(state):
    return b'Try again' in state.posix.dumps(1)
# should_abort = lambda state: b'Try again' in state.posix.dumps(1)

simulation.explore(find=is_successful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()   # 0 == sys.stdin.fileno()
    print('[+] Congratulations! Solution is: %s' % passwd)
else:
    raise Exception('Could not find the solution')