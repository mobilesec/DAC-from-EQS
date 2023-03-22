"""
This implementation of Set commitments with additional cross commitment and aggregation properties .
These commitments can be used to build SPSQE-UC signatures and their application delegatable anonymous credential.
See  the following for the details:
- Structure-Preserving Signatures on Equivalence Classes and Constant-Size Anonymous Credentials" by Fuchsbauer1 et al.,
- (PETS) Practical, Efficient, Delegatable Ano nymous Credentials through SPSEQ-UC, by Mir et al.,
@Author: Omid Mir
"""
from bplib.bp import BpGroup
from binascii import hexlify
from hashlib import sha256
from numpy.polynomial.polynomial import polyfromroots
from petlib.bn import Bn
from core.util import convert_mess_to_bn, ec_sum, product_GT, eq_dh_relation


class SetCommitment:
    def __init__(self, max_cardinal = 1):
        """
        Initializes a SetCommitment object.

        :param BG: bilinear pairing groups
        :param max_cardinal: the maximum cardinality t (default value is 1)
        """
        global group, max_cardinality
        max_cardinality = max_cardinal
        group = BG = BpGroup()

    @staticmethod
    def setup():
        """
        A static method to generate public parameters.

        :return: a tuple containing the public parameters and alpha_trapdoor
        """
        g_1, g_2 = group.gen1(), group.gen2()
        order = group.order()
        alpha_trapdoor = order.random()
        pp_commit_G1 = [g_1.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)]
        pp_commit_G2 = [g_2.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)]
        param_sc = (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group)
        return param_sc, alpha_trapdoor

    def commit_set(self, param_sc,  mess_set_str):
        """
          Commits to a set.

        :param param_sc: public parameters as P^ai, P_hat^ai, P = g1, P_hat = g2, Order, BG
        :param mess_set_str: a message set as a string

        :return: a set commitment and related opening information
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc

        # convert string to Zp
        mess_set = convert_mess_to_bn(mess_set_str)
        monypol_coeff = polyfromroots(mess_set)
        rho = group.order().random()

        # create group elements using the coefficent and public info
        coef_points = [(pp_commit_G1.__getitem__(i)).mul(monypol_coeff[i])for i in range(len(monypol_coeff))]

        # create a set commitment and opening info
        pre_commit = ec_sum(coef_points)
        commitment = pre_commit.mul(rho)
        open_info = rho
        return (commitment, open_info)


    def open_set(self, param_sc, commitment, open_info, mess_set_str):
        """
        Verifies the opening information of a set.

        :param param_sc: public parameters
        :param commitment: the set commitment
        :param open_info: the opening info of commitment
        :param mess_set_str: the message set
        :return: true if evolution is correct, false otherwise
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc

        mess_set = convert_mess_to_bn(mess_set_str)
        monypol_coeff = polyfromroots(mess_set)

        #pre compitation to recompute the commitment
        coef_points = [(pp_commit_G1.__getitem__(i)).mul(monypol_coeff[i])for i in range(len(monypol_coeff))]
        pre_commit = ec_sum(coef_points)
        re_commit = pre_commit.mul(open_info)

        #check if the regenerated commitment is match with the orginal commitment
        return re_commit == commitment

    def open_subset(self, param_sc, mess_set_str, open_info, subset_str):
        """
        Generates a witness for the subset

        :param param_sc: public parameters
        :param mess_set_str: the messagfe set
        :param open_info: opening information
        :param subset_str: a subset of the message set

        :return: a witness for the subset
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc

        # convert the string to BN elements
        mess_set = convert_mess_to_bn(mess_set_str)
        mess_subset_t = convert_mess_to_bn(subset_str)

        #Checks if mess_subset is a subset of mess_set
        def is_subset(mess_set, mess_subset_t):
            chcker = None
            if len(mess_subset_t) > len(mess_set):
                return False
            else:
                for item in mess_subset_t:
                    if (item in mess_set):
                        chcker = True
                    else:
                        chcker = False
            return chcker

        # compute a witness for subset mess_subset_t
        if is_subset(mess_set, mess_subset_t) == True:
            create_witn_elements = [item for item in mess_set if item not in mess_subset_t]
            coeff_witn = polyfromroots(create_witn_elements)
            witn_groups = [(pp_commit_G1.__getitem__(i)).mul(coeff_witn[i]) for i in range(len(coeff_witn))]
            witn_sum = ec_sum(witn_groups)
            witness = witn_sum.mul(open_info)
            return witness
        else:
            print("It is Not a subset")
            return False

    def verify_subset(self, param_sc, commitment, subset_str, witness):
        """
        Verifies if witness proves that subset_str is a subset of the original message set.


        :param param_sc: set commitment public parameters
        :param commitment: commitment
        :param subset_str: subset message
        :param witness: witness to prove subset message in message set
        :return: 0 or 1
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc
        # convert messagse to BN type
        mess_subset_t = convert_mess_to_bn(subset_str)
        # compute a polynomial for message set
        coeff_t = polyfromroots(mess_subset_t)
        subset_group_elements =[(pp_commit_G2.__getitem__(i)).mul(coeff_t[i])for i in range(len(coeff_t))]
        subset_elements_sum = ec_sum(subset_group_elements)

        return group.pair(witness, subset_elements_sum) == group.pair(commitment, g_2)

 
""" Here is CrossSetCommitment that extends the Set Commitment to provide aggregation witness and a batch verification """
 
class CrossSetCommitment(SetCommitment):
    def __init__(self, max_cardinal):
        SetCommitment.__init__(self, max_cardinal)

    def aggregate_cross(self, witness_vector, commit_vector):
        """
        Computes an aggregate proof of valid subsets of a set of messages.

        :param witness_vector: a vector of witnessess
        :param commit_vector: the commitment vector

        :return: a proof which is a aggregate of witnesses and shows all subsets are valid for respective sets
        """

        witnessness_group_elements = list()
        for i in range(len(witness_vector)):
            """ generates a Bn challenge t_i by hashing a number of EC points """
            Cstring = b",".join([hexlify(commit_vector[i].export())])
            chash = sha256(Cstring).digest()
            hash_i = Bn.from_binary(chash)
            witnessness_group_elements.append(witness_vector[i].mul(hash_i))
            # pi = (list_W[i+1] ** t_i).add(pi)
            # comute pi as each element of list power to t_i
        proof = ec_sum(witnessness_group_elements)
        return proof

    def verify_cross(self, param_sc, commit_vector, subsets_vector_str, proof):
        """
        Verifies an aggregate proof of valid subsets of a set of messages.

        :param param_sc: public parameters
        :param commit_vector: the set commitment vector
        :param subsets_vector_str: the message sets vector
        :param proof: a proof which is a aggregate of witnesses

        :return: 1 or 0
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc

        # create a union of sets
        def union(subsets_vector):
            set_s = subsets_vector[0]
            for i in range(1, len(subsets_vector)):
                set_s = set_s + subsets_vector[i]
            return set_s

        # create a set that is not intersection of two other sets
        def not_intersection(list_S, list_T):
            set_s_not_t = [value for value in list_S if value not in list_T]
            return set_s_not_t

        # convert message str into the BN
        subsets_vector = [convert_mess_to_bn(item) for item in subsets_vector_str]
        set_s = union(subsets_vector)
        coeff_set_s = polyfromroots(set_s)

        # compute right side of veriication
        set_s_group_elements = [(pp_commit_G2.__getitem__(i)).mul(coeff_set_s[i])for i in range(len(coeff_set_s))]
        set_s_elements_sum = ec_sum(set_s_group_elements)
        right_side = group.pair(proof, set_s_elements_sum)
        set_s_not_t = [not_intersection(set_s, subsets_vector[i]) for i in range(len(subsets_vector))]

        # compute left side of veriication
        vector_GT = list()
        for j in range(len(commit_vector)):
            coeff_s_not_t = polyfromroots(set_s_not_t[j])
            listpoints_s_not_t = [(pp_commit_G2.__getitem__(i)).mul(coeff_s_not_t[i]) for i in
                                  range(len(coeff_s_not_t))]
            temp_sum = ec_sum(listpoints_s_not_t)
            Cstring = b",".join([hexlify(commit_vector[j].export())])
            chash = sha256(Cstring).digest()
            hash_i = Bn.from_binary(chash)
            GT_element = group.pair(commit_vector[j], hash_i * temp_sum)
            vector_GT.append(GT_element)
        left_side = product_GT(vector_GT)
        # check both sides
        return right_side.eq(left_side)



