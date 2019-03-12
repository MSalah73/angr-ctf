import re
import angr
import claripy
import sys

def main(argv):
  path_to_binary = argv[1]
  project = angr.Project(path_to_binary)

  start_address = 0x8048619
  initial_state = project.factory.blank_state(addr=start_address)

  # The binary is calling scanf("%8s %8s %8s %8s").
  # (!)
  size = 64
  password0 = claripy.BVS('password0', size)
  password1 = claripy.BVS('password1', size)
  password2 = claripy.BVS('password2', size)
  password3 = claripy.BVS('password3', size)

  # Determine the address of the global variable to which scanf writes the user
  # input. The function 'initial_state.memory.store(address, value)' will write
  # 'value' (a bitvector) to 'address' (a memory location, as an integer.) The
  # 'address' parameter can also be a bitvector (and can be symbolic!).
  # (!)
  password0_address = 0xbf44e18
  initial_state.memory.store(password0_address, password0)
  password1_address = 0xbf44e10
  initial_state.memory.store(password1_address, password1)
  password2_address = 0xbf44e08
  initial_state.memory.store(password2_address, password2)
  password3_address = 0xbf44e00
  initial_state.memory.store(password3_address, password3)

  simulation = project.factory.simgr(initial_state)

  def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if re.findall(r'Good Job.', stdout_output):
	return True
    # Return whether 'Good Job.' has been printed yet.
    # (!)
    return False # :boolean


  def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if re.findall(r'Try again.', stdout_output):
	return True
    # Return whether 'Good Job.' has been printed yet.
    # (!)
    return False # :boolean

  simulation.explore(find=is_successful, avoid=should_abort)

  if simulation.found:
    solution_state = simulation.found[0]

    # Solve for the symbolic values. We are trying to solve for a string.
    # Therefore, we will use eval, with named parameter cast_to=str
    # which returns a string instead of an integer.
    # (!)
    solution0 = solution_state.se.eval(password0,cast_to=str)
    solution1 = solution_state.se.eval(password1,cast_to=str)
    solution2 = solution_state.se.eval(password2,cast_to=str)
    solution3 = solution_state.se.eval(password3,cast_to=str)
    solution = [solution0, solution1, solution2, solution3] 

    print solution3, solution2, solution1, solution0
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
