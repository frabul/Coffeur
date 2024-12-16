from Coffeur.Coffeur import Coffeur, Variable

def print_var_and_children(var : Variable, depth=0):
    # print path, address size for each member of the struct if it is a base type, pointer, or array
    # otherwise reiterate through the struct 
    padding = "    " * depth if depth > 0 else ""
    print(f'{padding}{var.type.name}  {var.path}  0x{var.address:X}  {var.get_size():d}')
    depth = depth + 1
    if var.type.final_type().is_struct() or var.type.final_type().is_union():
        for mem in var.get_members():
            print_var_and_children(mem, depth)

            

c = Coffeur("p2.out", "p2.bin")
var = c.get_variable("Sens")
print(var)
print_var_and_children(var)      

