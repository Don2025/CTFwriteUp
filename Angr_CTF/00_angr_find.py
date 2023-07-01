import angr

project = angr.Project('./00_angr_find')
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)
simulation.explore(find=0x8048678)
if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(0))
else:
    raise Exception('Could not find the solution')