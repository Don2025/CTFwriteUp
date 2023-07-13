import angr
import claripy

path_to_binary = './11_angr_sim_scanf'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
scanf_symbol = '__isoc99_scanf'
class ReplaceScanf(angr.SimProcedure):
    def run(self, format_string, param0, param1):
        scanf0 = claripy.BVS('scanf0', 32)
        scanf1 = claripy.BVS('scanf1', 32)
        scanf0_addr = param0
        self.state.memory.store(scanf0_addr, scanf0, endness=project.arch.memory_endness)
        scanf1_addr = param1
        self.state.memory.store(scanf1_addr, scanf1, endness=project.arch.memory_endness)
        self.state.globals['solutions'] = (scanf0, scanf1)

project.hook_symbol(scanf_symbol, ReplaceScanf())
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    (solution0, solution1) = solution_state.globals['solutions']
    passwd0 = solution_state.solver.eval(solution0)
    passwd1 = solution_state.solver.eval(solution1)
    print('[+] Congratulations! Solution is: {} {}'.format(passwd0, passwd1))
else:
    raise Exception('Could not find the solution')