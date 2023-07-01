import angr

project = angr.Project('./02_angr_find_condition')
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)

# set expected function
def is_succcessful(state):
    return b'Good Job' in state.posix.dumps(1)

# set unexpected function
def should_abort(state):
    return b'Try again' in state.posix.dumps(1)

simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(0))
else:
    raise Exception('Could not find the solution')