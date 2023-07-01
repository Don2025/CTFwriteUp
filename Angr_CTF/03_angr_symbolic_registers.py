import angr
import claripy

project = angr.Project('./03_angr_symbolic_registers')
start_address = 0x8048980
initial_state = project.factory.entry_state(addr=start_address)
# create some bitvector symbols to assign the registers.
password0 = claripy.BVS('p0', 32)
initial_state.regs.eax = password0
password1 = claripy.BVS('p1', 32)
initial_state.regs.ebx = password1
password2 = claripy.BVS('p2', 32)
initial_state.regs.edx = password2

# set expected function to judge whether the output is succeessful according to the state.
def is_succcessful(state):
    return b'Good Job' in state.posix.dumps(1)

# set unexpected function
def should_abort(state):
    return b'Try again' in state.posix.dumps(1)

simulation = project.factory.simgr(initial_state)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd0 = solution_state.solver.eval(password0)
    passwd1 = solution_state.solver.eval(password1)
    passwd2 = solution_state.solver.eval(password2)
    print(' '.join(map('{:x}'.format, [passwd0, passwd1, passwd2])))
else:
    raise Exception('Could not find the solution')