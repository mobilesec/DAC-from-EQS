"""
This implementation of SPSQE-UC signature (called as EQC_Sign class). It uses Set commitments as an ingredient
See the following for the details
 -Practical Delegatable Anonymous Credentials From Equivalence Class Signatures, PETS 2023.
   https://eprint.iacr.org/2022/680
@Author: Omid Mir
"""

from numpy.polynomial.polynomial import polyfromroots
from core.set_commit import CrossSetCommitment
from core.util import *

class EQC_Sign:
    def __init__(self, max_cardinal = 1):
        """ Initializes the EQC_Sign class """
        global max_cardinality, group
        group = BpGroup()
        max_cardinality = max_cardinal
        self.csc_scheme =  CrossSetCommitment(max_cardinal)

    def setup(self):
        """
        Sets up the signature scheme by creating public parameters and a secret key
        :return: public parameters and secret key
        """
        pp_sign, alpha = self.csc_scheme.setup()
        return pp_sign, alpha

    def sign_keygen(self, pp_sign, l_message):
        """
        Generates signing key pair given the public parameters and length of the message

        :param pp_sign: signature public parameters
        :param l_message: length of the message vector

        :return: signing key pair as sk and pk
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign
        # compute secret keys
        sk = [order.random() for _ in range(0, l_message)]
        # compute public keys
        vk = [sk[i] * g_2 for i in range(len(sk))]
        # compute X_0 keys that is used for delegation
        X_0 = sk[0] * g_1
        vk.insert(0, X_0)
        return (sk, vk)

    def user_keygen(self, pp_sign):
        """
        Generates a user key pair given the public parameters

        :param pp_sign: signature public parameters
        :return: a user key pair
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign
        # pick a random and compute key pair for users
        sk_u = order.random()
        pk_u = sk_u * g_1
        return (sk_u, pk_u)

    def encode(self, pp_sign, mess_set):
        """
        Encodes a message set into a set commitment with opening information

        :param pp_sign: signature public parameters
        :param mess_set: a message set

        :return: a commitment and opening information
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign
        param_sc = (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group)
        # commit to set using csc scheme (cross set commitment)
        commitment, opening_info =  self.csc_scheme.commit_set(param_sc, mess_set)
        return (commitment, opening_info)

    def rndmz_commit(self, commitment_vector, opening_vector, mu):
        """
        Randomizes a commitment and opening vectors with a given randomness mu.

        :param commitment_vector:
        :param opening_vector:
        :param mu: a randomness
        :return: a randomized commitment and opening information
        """
        rndmz_commit_vector = [mu * item for item in commitment_vector]
        rndmz_opening_vector = [mu * item for item in opening_vector]
        return (rndmz_commit_vector, rndmz_opening_vector)

    def rndmz_pk(self,pp_sign, pk_u, psi, chi):
        """
        Randomizes a public key with two given randomness psi and chi.

        :param pp_sign: signature public parameters
        :param pk_u: user public key
        :param psi: randomness uses to randomize public key
        :param chi: randomness uses to randomize public key

        :return: randomized public key
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign
        # randomize pk as described in the paper
        rndmz_pk_u= psi * (pk_u + chi * g_1)
        return rndmz_pk_u

    def sign(self, pp_sign, pk_u, sk, messages_vector, k_prime = None):
        """
        Generates a signature for the commitment and related opening information along with update key.

        :param pp_sign:signature public parameters
        :param pk_u: user public key
        :param sk: signing key
        :param messages_vector: message vector
        :param k_prime: index defining number of delegatable attributes  in update key uk

        :return: signature for the commitment and related opening information along with update key
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign
        commitment_vector = []
        opening_vector = []

        # encode all messagse sets of the messages vector as set commitments
        for mess in messages_vector:
            commitment, opening = self.encode(pp_sign, mess)
            commitment_vector.append(commitment)
            opening_vector.append(opening)

        # pick randomness y
        y = order.random()
        # compute sign -> sigma = (Z, Y, hat Ym T)
        list_Z = [sk[i + 2] * commitment_vector[i] for i in range(len(commitment_vector))]
        temp_point = ec_sum(list_Z)
        Z = y.mod_inverse(order) * temp_point
        Y = y * g_1
        Y_hat = y * g_2
        T = sk[1] * Y + sk[0] * pk_u
        sigma = (Z, Y, Y_hat, T)

        #check if the update keyis requested then compute update key using k_prime, otherwise compute signature without it
        if k_prime != None:
            if k_prime > len(messages_vector):
                usign = {}
                for item in range(len(messages_vector) + 1, k_prime + 1):
                    UK = [(y.mod_inverse(order) * sk[item + 1]) * pp_commit_G1[i] for i in range(max_cardinality)]
                    usign[item] = UK
                    update_key = usign
                return (sigma, update_key, commitment_vector, opening_vector)
            else:
                print("not a good index, k_prime index should be greater  than message length")
        else:
            return (sigma, commitment_vector, opening_vector)

    def change_rep(self, pp_sign, vk, pk_u, commitment_vector, opening_vector, sigma, mu, psi, B=False, update_key=None):
        """
          Change representation of the signature message pair to a new commitment vector and user public key.

        :param pp_sign: signature public parameters
        :param vk: verification key
        :param pk_u: user public key
        :param commitment_vector: commitment vector
        :param opening_vector: opening information vector related to commitment vector
        :param sigma: signature
        :param mu: randomness is used to randomize commitment vector and signature accordingly
        :param psi: randomness is used to randomize commitment vector and signature accordingly
        :param B: a falge to determine if it needs to randomize upda key as well or not
        :param update_key: update key, it can be none in the case that no need for randomization

        :return: a randomization of message-signature pair
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign
        # pick randomness
        chi = order.random()

        # randomize Commitment and opening vectors and user public key with randomness mu, chi
        rndmz_commitment_vector, rndmz_opening_vector = self.rndmz_commit(commitment_vector, opening_vector, mu)
        rndmz_pk_u = self.rndmz_pk(pp_sign, pk_u, psi, chi)

        # adapt the signiture for the randomized coomitment vector and PK_u_prime
        (Z, Y, Y_hat, T) = sigma
        Z_prime = (mu * psi.mod_inverse(order)) * Z
        Y_prime = psi * Y
        Y_hat_prime = psi * Y_hat
        T_prime = psi * (T + chi * vk[0])
        sigma_prime = (Z_prime, Y_prime, Y_hat_prime, T_prime)

        # Check if it is allowed to randomize update_key for further delegation, if yes then randomize it
        if B == True and update_key != None:
            usign = update_key
            usign_prime = {}
            for key in usign:
                update_keylist = usign.get(key)
                mainop = [(mu * psi.mod_inverse(order)) * update_keylist[i] for i in range(max_cardinality)]
                usign_prime[key] = mainop
            rndmz_update_key = usign_prime
            return (sigma_prime, rndmz_update_key, rndmz_commitment_vector, rndmz_opening_vector, rndmz_pk_u, chi)
        else:
            return (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, rndmz_pk_u, chi)

    def change_rel(self, pp_sign, message_l, index_l, sigma, commitment_vector, opening_vector, update_key, mu=1):
        """
         Update the signature for a new commitment vector including 𝐶_L for message_l using update_key

        :param pp_sign: signature public parameters
        :param message_l: message set at index l that will be added in message vector
        :param index_l: index l denotes the next position of message vector that needs to be fixed
        :param sigma: signature
        :param commitment_vector: signed commitment vector
        :param opening_vector:opening information related to commitment vector
        :param update_key: updates key can add more messages and commitment into signature message pair
        :param mu: randomness

        :return: a new singitre including the message set l
        """
        usign = update_key
        Z, Y, Y_hat, T = sigma
        commitment_L, opening_L = self.encode(pp_sign, message_l)
        rndmz_commitment_L, rndmz_opening_L = mu * commitment_L, mu * opening_L

        # add the commitment CL for index L into the signature, the update commitment vector and opening for this new commitment
        if (index_l in usign):
            set_l = convert_mess_to_bn(message_l)
            monypolcoefficient = polyfromroots(set_l)
            list = usign.get(index_l)
            points_uk_i = [(list[i]).mul(monypolcoefficient[i]) for i in range(len(monypolcoefficient))]
            ret = ec_sum(points_uk_i)
            gama_l = ret.mul(opening_L)
            Z_tilde = Z + gama_l
            sigma_tilde = (Z_tilde, Y, Y_hat, T)
            commitment_vector.append(rndmz_commitment_L)
            opening_vector.append(rndmz_opening_L)
            return (sigma_tilde, commitment_L, opening_L, commitment_vector, opening_vector)
        else:
            raise("index_l is the out of scope")


    def send_convert_sig(self , vk, sk_u, sigma):
        """
        create a temporary (orphan) signature for use in the convert signature algorithm.

        :param vk: verification key
        :param sk_u: user secre key
        :param sigma: a signature
        :return: a tempretory (orpha) signature for convert signature algo
        """
        (Z, Y, Y_hat, T) = sigma
        # update component T of signature to remove the old key
        T_new = T + ((vk[0]*sk_u).neg())
        sigma_orpha = (Z, Y, Y_hat, T_new)
        return sigma_orpha

    def receive_convert_sig(self, vk, sk_r, sigma_orpha):
        """
        On input a temporary (orphan) signature and returns a new signature for the new public key.

        :param vk: verification key
        :param sk_r: secret key if a new user
        :param sigma_orpha: a temporary (orphan) signature

        :return: a new signature for the new public key
        """
        (Z, Y, Y_hat, T) = sigma_orpha
        # update component T of signature with a new key
        T_new = T + (vk[0] * sk_r)
        # output sigma_prime as new sign valid for the new key
        sigma_prime = (Z, Y, Y_hat, T_new)
        return sigma_prime

    def verify(self, pp_sign, vk, pk_u, commitment_vector, sigma):
        """
        checks if the signature is valid

        :param pp_sign: signature public parameters
        :param vk: verification key
        :param pk_u: user public key
        :param commitment_vector: signed commitment vector
        :param sigma: signature for commitment vector

        :return: check if signature is valid: 0/1
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign
        (Z, Y, Y_hat, T) = sigma

        # statment 1
        right_side = group.pair(Z, Y_hat)
        pairing_op = [group.pair(commitment_vector[j], vk[j + 3]) for j in range(len(commitment_vector))]
        # statment 2
        left_side = product_GT(pairing_op)
        return (group.pair(Y, g_2) == group.pair(g_1, Y_hat)) and (group.pair(T, g_2) == group.pair(Y, vk[2]) * group.pair(pk_u, vk[1])) and (
                right_side == left_side)
