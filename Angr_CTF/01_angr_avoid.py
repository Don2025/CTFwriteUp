import angr

project = angr.Project('./01_angr_avoid')
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)
simulation.explore(find=0x80485e5, avoid=0x80485a8)
if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(0))
else:
    raise Exception('Could not find the solution')