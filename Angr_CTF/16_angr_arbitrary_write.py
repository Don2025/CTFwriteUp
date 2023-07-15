import angr
import claripy

path_to_binary = './16_angr_arbitrary_write'
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
scanf_symbol = '__isoc99_scanf'
class ReplaceScanf(angr.SimProcedure):
    def run(self, format_string, param0, param1):
        scanf0 = claripy.BVS('scanf0',  32)
        scanf1 = claripy.BVS('scanf1', 20*8)
        for ch in scanf1.chop(bits=8):
            self.state.add_constraints(ch >= b'0', ch <= b'z')
        scanf0_address = param0
        self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
        scanf1_address = param1
        self.state.memory.store(scanf1_address, scanf1)
        self.state.globals['solutions'] = (scanf0, scanf1)

project.hook_symbol(scanf_symbol, ReplaceScanf())

def check_strncpy(state):
    strncpy_dest = state.memory.load(state.regs.esp+4, 4, endness=project.arch.memory_endness)
    strncpy_src = state.memory.load(state.regs.esp+8, 4, endness=project.arch.memory_endness)
    strncpy_len = state.memory.load(state.regs.esp+12, 4, endness=project.arch.memory_endness)
    src_content = state.memory.load(strncpy_src, strncpy_len)
    if state.solver.symbolic(strncpy_dest) and state.solver.symbolic(src_content):
        password_value = b'NDYNWEUJ'
        password_buffer = 0x57584344
        src_hold_password = src_content[-1:-64] == password_value
        dest_equals_buffer = strncpy_dest == password_buffer
        copied_state = state.copy()
        if copied_state.satisfiable(extra_constraints=(src_hold_password, dest_equals_buffer)):
            state.add_constraints(src_hold_password, dest_equals_buffer)
            return True
        else:
            return False
    else:
        return False

simulation = project.factory.simgr(initial_state)
strncpy_plt = project.loader.main_object.plt['strncpy']  # 0x8048410
is_succcessful = lambda state: check_strncpy(state) if state.addr == strncpy_plt else False
simulation.explore(find=is_succcessful)
if simulation.found:
    solution_state = simulation.found[0]
    (solution0, solution1) = solution_state.globals['solutions']
    passwd0 = solution_state.solver.eval(solution0)
    passwd1 = solution_state.solver.eval(solution1, cast_to=bytes).decode()
    print('[+] Congratulations! Solution is: {} {}'.format(passwd0, passwd1))
else:
    raise Exception('Could not find the solution')