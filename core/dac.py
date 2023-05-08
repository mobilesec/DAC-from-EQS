"""
This is implementation of delegatable anonymous credential using SPSQE-UC signatures and set commitment.
See  the following for the details:
- Practical Delegatable Anonymous Credentials From Equivalence Class Signatures, PETS 2023.
   https://eprint.iacr.org/2022/680
@Author: Omid Mir
"""

from bplib.bp import BpGroup
from core.set_commit import CrossSetCommitment
from core.spseq_uc import EQC_Sign
from core.zkp import ZKP_Schnorr_FS, Damgard_Transfor

class DAC:
    def __init__(self, t, l_message):
        """
        Initialize the DAC scheme.

        :param group: bilinear group BpGroup
        :param t: max cardinality
        :param l_message: the max number of the messages

        :return: public parameters including sign and set comment and zkp, and object of SC and sign and zkp schemes
        """
        global group, order
        group = BpGroup()
        order = BpGroup().order()
        self.t = t
        self.l_message = l_message
        # create objects of underlines schemes
        self.spseq_uc = EQC_Sign(t)
        self.setcommit = CrossSetCommitment(t)
        self.nizkp = ZKP_Schnorr_FS(group)
        self.zkp = Damgard_Transfor(group)

    def setup(self):
        """
         the DAC scheme public parameters
        """
        # create public parameters and signing pair keys
        pp_sign, alpha = self.spseq_uc.setup()
        (sk_ca, vk_ca) = self.spseq_uc.sign_keygen(pp_sign, l_message=self.l_message)
        pp_zkp = self.zkp.setup(group)
        pp_nizkp = self.nizkp.setup()
        (G, g, o) = pp_nizkp

        "create proof of vk and alpha trpdoor -> vk_stm and alpha_stm are the statements need to be proved "
        X_0 = vk_ca.pop(0)
        vk_stm = vk_ca.copy()
        proof_vk = self.nizkp.non_interact_prove(pp_nizkp, stm=vk_stm, secret_wit=sk_ca)
        alpha_stm = alpha * g
        proof_alpha = self.nizkp.non_interact_prove(pp_nizkp, stm=alpha_stm, secret_wit=alpha)
        vk_ca.insert(0, X_0)
        pp_dac = (pp_sign, pp_zkp, pp_nizkp, vk_ca)
        return (pp_dac, proof_vk, vk_stm, sk_ca, proof_alpha, alpha_stm)

    def user_keygen(self, pp_dac):
        """
        Generate a key pair for a user.

        :param pp_dac:  public parameters

        :return: user key pair
        """
        (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
        (usk, upk) = self.spseq_uc.user_keygen(pp_sign)
        return (usk, upk)

    def nym_gen(self, pp_dac, usk, upk):
        """
        Generate a new pseudonym and auxiliary information.

        :param pp_dac:  public parameters
        :param upk: user public key ( or pseudonym)

        :return: a new pseudonym and auxiliary information
        """
        (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
        (G, g, o, h) = pp_zkp
        # pick randomness
        psi, chi = order.random(), order.random()

        # create a nym and aux for it
        nym = self.spseq_uc.rndmz_pk(pp_sign, upk, psi, chi)
        secret_wit = psi * (usk + chi)

        # create a proof for nym
        (pedersen_commit, pedersen_open) = self.zkp.announce()
        (open_randomness, announce_randomnes, announce_element) = pedersen_open
        state = ['schnorr', g, h, pedersen_commit.__hash__()]
        challenge = self.zkp.challenge(state)
        response = self.zkp.response(challenge, announce_randomnes, stm=nym, secret_wit=secret_wit)
        proof_nym_u = (challenge, pedersen_open, pedersen_commit, nym, response)

        return (nym, secret_wit, proof_nym_u)

    def issue_cred(self, pp_dac, attr_vector, sk, nym_u, k_prime, proof_nym_u):
        """
        Issues a root credential to a user.

        :param pp_dac: public parameters
        :param Attr_vector: attribute vector
        :param sk: signing key sk_ca in paper
        :param nym_u: pseudonym of the user who gets credential
        :param k_prime: index need for update key uk
        :param proof_nym_u: proof of pseudonym that need to be checked if it is correct

        :return: a root credential
        """
        (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
        challenge, pedersen_open, pedersen_commit, stm, response = proof_nym_u

        # check if proof of nym is correct
        if self.zkp.verify(challenge, pedersen_open, pedersen_commit, stm, response) == True:
            # check if delegate keys is provided
            if k_prime != None:
                (sigma, update_key, commitment_vector, opening_vector) = self.spseq_uc.sign(pp_sign, nym_u, sk, attr_vector, k_prime)
                cred = (sigma, update_key, commitment_vector, opening_vector)
                assert(self.spseq_uc.verify(pp_sign, vk_ca, nym_u, commitment_vector, sigma)), ValueError("signature/credential is not correct")
                return cred
            else:
                (sigma, commitment_vector, opening_vector) = self.spseq_uc.sign(pp_sign, nym_u, sk, attr_vector)
                cred = (sigma, commitment_vector, opening_vector)
                assert (self.spseq_uc.verify(pp_sign, vk_ca, nym_u, commitment_vector, sigma)), ValueError(
                    "signature/credential is not correct")
                return cred
        else:
            raise ValueError("proof of nym is not valid ")

    def proof_cred(self, pp_dac, nym_R, aux_R, cred_R, Attr, D):
        """
            Generates proof of a credential for a given pseudonym and selective disclosure D.

        :param pp_dac:public parameters
        :param nym_R: pseudonym of a user who wants to prove credentials to verifiers
        :param aux_R: auxiliary information related to the pseudonym
        :param cred_R: credential of pseudonym R that is needed to prove
        :param Attr: attributes vector in credential R
        :param D: the subset of attributes (selective disclose)

        :return: a proof of credential that is a credential P
        """
        (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
        (G, g, o, h) = pp_zkp
        (sigma, commitment_vector, opening_vector) = cred_R
        # pick randomness
        mu, psi = order.random(), order.random()
        # run change rep to randomize credential and user pk (i.e., create a new nym)
        (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi) = self.spseq_uc.change_rep \
            (pp_sign, vk_ca, nym_R, commitment_vector, opening_vector, sigma, mu, psi, B=False, update_key=None)

        # create an announcement
        (pedersen_commit, pedersen_open) = self.zkp.announce()
        (open_randomness, announce_randomnes, announce_element) = pedersen_open

        # get a challenge
        state = ['schnorr', g, h, pedersen_commit.__hash__()]
        challenge = self.zkp.challenge(state)

        # prover creates a respoonse (or proof)
        response = self.zkp.response(challenge, announce_randomnes, stm=nym_P, secret_wit= (aux_R + chi) * psi )
        proof_nym_p = (challenge, pedersen_open, pedersen_commit, nym_P, response)

        # create a witness for the attributes set that needed to be disclosed
        Witness = [self.setcommit.open_subset(pp_sign, Attr[i], rndmz_opening_vector[i], D[i]) for i in range(len(D))]
        list_C = [rndmz_commitment_vector[i] for i in range(len(D))]
        Witness_pi = self.setcommit.aggregate_cross(Witness, list_C)

        # output the whole proof
        proof = (sigma_prime, rndmz_commitment_vector, nym_P, Witness_pi, proof_nym_p)
        return proof

    def verify_proof(self, pp_dac, proof, D):
        """
        verify proof of a credential

        :param pp_dac:public parameters
        :param proof: a proof of credential satisfied subset attributes D
        :param D: subset attributes

        :return: 0/1
        """
        (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
        (sigma_prime, rndmz_commitment_vector, nym_P, Witness_pi, proof_nym_p) = proof
        (challenge, pedersen_open, pedersen_commit, nym_P, response) = proof_nym_p

        # filter set commitments regarding D
        list_C = [rndmz_commitment_vector[i] for i in range(len(D))]

        # check the proof is valid for D
        return self.setcommit.verify_cross(pp_sign, list_C, D, Witness_pi) and \
                self.zkp.verify(challenge, pedersen_open, pedersen_commit, nym_P, response) and self.spseq_uc.verify(pp_sign,    vk_ca, nym_P, rndmz_commitment_vector,sigma_prime) == True


    """
    This is the delegation phase or the issuing credential protocol in the paper between the delegator and delegatee. 
    """

    def delegator(self, pp_dac, cred_u, A_l, l, sk_u, proof_nym):
        """
        Create an initial delegatable credential from a user U to a user R (an interactive protocol)

        :param pp_dac: public parameters
        :param cred_u: delegator u credential
        :param A_l: additional attributes set can be added into credential
        :param l: index of the message set
        :param sk_u: secret key of the credential holder
        :param proof_nym: check proof of nym of user R

        :return: delegatable credential cred_R for a user R
        """
        (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
        challenge, pedersen_open, pedersen_commit, stm, response = proof_nym

        # check the proof
        assert self.zkp.verify(challenge, pedersen_open, pedersen_commit, stm, response)

        (sigma, update_key, commitment_vector, opening_vector) = cred_u
        # run change rep to add an attributes set l into the credential
        (Sigma_tilde, Commitment_L, Opening_L, Commitment_vector_new, Opening_vector_new) = self.spseq_uc.change_rel(pp_sign, A_l, l, sigma,
                                                                                                                commitment_vector, opening_vector, update_key)
        # run convert signature for sender to remove secret key for the credential
        sigma_orpha = self.spseq_uc.send_convert_sig(vk_ca, sk_u, Sigma_tilde)
        # output a new credential for the additional attribute set and  ready to be added a new user secret key
        cred_R = (sigma_orpha, Commitment_L, Opening_L, Commitment_vector_new, Opening_vector_new)
        return cred_R

    def delegatee(self, pp_dac, cred, A_l, sk_R, nym_R):
        """
        Create a delegatable credential to a user R

        :param pp_dac: public parameters
        :param cred: credential got from the delegator
        :param A_l: additional attributes set can be added into credential
        :param sk_R: secret key of delegatee R
        :param nym_R: c of delegatee nym_R

        :return: a final credential R for nym_R
        """
        (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_sign
        (sigma_orpha, Commitment_L, Opening_L, Commitment_vector_new, Opening_vector_new) = cred
        # convert signature receiver part to add the new user secret key into the credential
        sigma_change = self.spseq_uc.receive_convert_sig(vk_ca, sk_R, sigma_orpha)
        # pick randomness
        mu, psi = order.random(), order.random()
        # run changrep to randomize and hide the whole credential
        (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi) = self.spseq_uc.change_rep \
            (pp_sign, vk_ca, nym_R, Commitment_vector_new, Opening_vector_new, sigma_change, mu, psi, B=False,
             update_key=None)
        # output a new credential for the additional attribute set as well as the new user
        cred_R = (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi)
        return cred_R
