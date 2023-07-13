import angr
import claripy

path_to_binary = './10_angr_simprocedures'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
check_equal_symbol = 'check_equals_ORSDDWXHZURJRBDH'
class CheckEqual(angr.SimProcedure):
    def run(self, address, length):
        constrained_value = b'ORSDDWXHZURJRBDH'
        content = self.state.memory.load(address, length)
        return claripy.If(content == constrained_value, claripy.BVV(1, 32), claripy.BVV(0, 32))

project.hook_symbol(check_equal_symbol, CheckEqual())
simulation = project.factory.simgr(initial_state)
is_succcessful = lambda state: b'Good Job' in state.posix.dumps(1)
should_abort = lambda state: b'Try again' in state.posix.dumps(1)
simulation.explore(find=is_succcessful, avoid=should_abort)
if simulation.found:
    solution_state = simulation.found[0]
    passwd = solution_state.posix.dumps(0).decode()
    print('[+] Congratulations! Solution is: {}'.format(passwd))
else:
    raise Exception('Could not find the solution')