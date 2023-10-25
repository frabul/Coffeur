from Coffeur.Coffeur import Coffeur, Variable

c = Coffeur("p2.out", "p2.bin")
 

var = c.get_variable("flg_Stato_Rete_u.bit")
print(var)

