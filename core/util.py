from termcolor import colored
from coconut.scheme import *
from coconut.utils import *

# ==================================================
# Setup parameters:
# ==================================================

## this class generates bilinear pairing BG

class GenParameters:

    def __init__(self):
        self.e = BpGroup()
        self.g1, self. g2 = self.e.gen1(), self.e.gen2()
        self.Order = self.e.order()

    # getter methods
    def get_e(self):
        return self.e

    def get_Order(self):
        return self.Order

    def get_g1(self):
        return self.g1

    def get_g2(self):
        return self.g2


# ==================================================
# others
# ==================================================

def ec_sum(list):
    """ sum EC points list """
    ret = list[0]
    for i in range(1, len(list)):
        ret = ret + list[i]
    return ret

def product_GT(list_GT):
    """ pairing product equations of a list """
    ret_GT = list_GT[0]
    for i in range(1, len(list_GT)):
        ret_GT = ret_GT * (list_GT[i])
    return ret_GT

# ==================================================
# Attribute Representation:
# ==================================================
def eq_relation(message_vector, mu):
    message_representive = []
    if isinstance(message_vector[0], list):
        for message in message_vector:
             message_representive.append([message[i] * mu  for i in range(len(message))])
    elif isinstance(message_vector, list):
        message_representive = [message * mu for message in message_vector]
    else:
        print("not correct format, insert a list of group elements or a list of list")
    return message_representive

def eq_dh_relation(dh_message_vector, mu, opsilon):
    dh_message_representive = [[item[0] * mu, item[1] * opsilon] for item in dh_message_vector]
    return dh_message_representive


def convert_mess_to_groups(message_vector):
    """
    :param: get a vector of strings or vector of vector strings as message_vector
    :return: return a vector of group elements in G1
    """
    message_group_vector = []
    if type(message_vector[0])== str:
        message_group_vector = [BpGroup().hashG1(message.encode()) for message in message_vector]
    else:
        for message in message_vector:
            temp = [BpGroup().hashG1(message[i].encode()) for i in range(len(message))]
            message_group_vector.append(temp)

    return message_group_vector

def convert_mess_to_bn(messages):
    if type(messages)==str:
        Conver_message = Bn.from_binary(str.encode(messages))
    elif isinstance(messages, set) or isinstance(messages, list):
        try:
            Conver_message = list(map(lambda item: Bn.from_binary(str.encode(item)), messages))
        except:
            print(colored('insert all messages as string', 'green'))
    else:
        print(colored('message type is not correct', 'green'))

    return Conver_message



# ==================================================
# Trapdoor (pedersen) commitment
# ==================================================

def pedersen_setup(group):
   """ generate an pedersen parameters with a Trapdoor d (only used in POK) """
   g = group.gen1()
   o = group.order()
   group =group
   d = o.random()
   h = d * g
   trapdoor = d
   pp_pedersen = (group, g, o, h)
   return (pp_pedersen, trapdoor)


def pedersen_committ(pp_pedersen, m):
    """ commit/encrypts the values of a message (g^m) """
    (G, g, o, h) = pp_pedersen
    r = o.random()
    if type(m) is Bn:
        pedersen_commit = r * h + m * g
    else:
        pedersen_commit = r * h + m
    pedersen_open = (r, m)
    return (pedersen_commit, pedersen_open)

def pedersen_dec(pp_pedersen, pedersen_open, pedersen_commit):
    """ decrypts/decommit the message """
    (G, g, o, h) = pp_pedersen
    (r, m) = pedersen_open
    if type(m) == Bn:
        c2 = r * h + m * g
    else:
        c2 = r * h + m
    return c2== pedersen_commit



