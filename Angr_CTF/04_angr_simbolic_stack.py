import angr
import claripy

project = angr.Project('./04_angr_symbolic_stack')
start_address = 0x8048697
initial_state = project.factory.blank_state(addr=start_address)
initial_state.regs.ebp = initial_state.regs.esp
password0 = claripy.BVS('p0', 32)
password1 = claripy.BVS('p1', 32)
# simulate the stack
padding = 0x8
initial_state.regs.esp -= padding
initial_state.stack_push(password0)
initial_state.stack_push(password1)
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd0 = solution_state.solver.eval(password0)
    passwd1 = solution_state.solver.eval(password1)
    print('[+] Congratulations! Solution is: {} {}'.format(passwd0, passwd1))
else:
    raise Exception('Could not find the solution')