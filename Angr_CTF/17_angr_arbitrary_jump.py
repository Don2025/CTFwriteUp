import angr
import claripy

path_to_binary = './17_angr_arbitrary_jump'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
scanf_symbol = '__isoc99_scanf'
class ReplaceScanf(angr.SimProcedure):
    def run(self, format_string, input_buffer_address):
        input_buffer = claripy.BVS('input_buffer',  64*8)
        for ch in input_buffer.chop(bits=8):
            self.state.add_constraints(ch >= b'0', ch <= b'z')
        self.state.memory.store(input_buffer_address, input_buffer)
        self.state.globals['solution'] = input_buffer

project.hook_symbol(scanf_symbol, ReplaceScanf())
simulation = project.factory.simgr(
    initial_state, save_unconstrained=True,
    stashes={
      'active' : [initial_state],
      'unconstrained' : [],
      'found' : [],
      'not_needed' : []
    })
while ((simulation.active or simulation.unconstrained) and (not simulation.found)):
    for unconstrained_state in  simulation.unconstrained:
        simulation.move('unconstrained', 'found')
    simulation.step()
print_good_address = project.loader.main_object.get_symbol('print_good').rebased_addr  # 0x42585249 
if simulation.found:
    solution_state = simulation.found[0]
    solution_state.add_constraints(solution_state.regs.eip == print_good_address)
    solution = solution_state.globals['solution']
    passwd = solution_state.solver.eval(solution, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: %s' % passwd)
else:
    raise Exception('Could not find the solution')