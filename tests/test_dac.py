"""
This is a Test (and example of how it works) of DAC protocol section 4 in the paper: dac.py
This file contains unit tests for the functions in dac.py.
It tests the functions with different inputs and verifies that they produce the expected outputs.
"""

from bplib.bp import BpGroup
from core.dac import DAC
from core.spseq_uc import EQC_Sign
from core.zkp import ZKP_Schnorr_FS

## messages sets as string type (attributes)
message1_str = ["age = 30", "name = Alice ", "driver license = 12"]
message2_str = ["genther = male", "componey = XX ", "driver license type = B"]
## vector of messages sets
Attr_vector=[message1_str, message2_str]
## subset of each message set
SubList1_str = ["age = 30", "name = Alice "]
SubList2_str = ["genther = male", "componey = XX "]


def setup_module(module):
    """Set up the DAC and return the necessary parameters and objects."""
    print("__________Setup___Test DAC ________")
    global EQ_Sign, dac, spseq_uc
    global pp, pp_dac, sk_ca, BG

    # create sign and nizk objest
    BG = BpGroup()
    nizkp = ZKP_Schnorr_FS(BG)
    spseq_uc = EQC_Sign(5)

    # create dac obj, where t is max cardinality and l_message: the max number of the messagses
    dac = DAC(t = 5, l_message = 10)

    # run setup to create public information of dac schemes
    (pp_dac, proof_vk, vk_stm, sk_ca, proof_alpha, alpha_stm) = dac.setup()
    (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac

    ## check if nizp of signing keys is correct
    assert (nizkp.non_interact_verify(pp_nizkp, vk_stm, proof_vk))
    assert (nizkp.non_interact_verify(pp_nizkp, alpha_stm, proof_alpha))
def test_root_cred() -> None:
    """Test the creation of a root credential."""
    (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
    ## create user key pair
    (usk, upk) = dac.user_keygen(pp_dac)
    ## create nym  and a proof for nym
    (nym_u, secret_nym_u, proof_nym_u) = dac.nym_gen(pp_dac, usk, upk)
    ## create a root credential
    cred = dac.issue_cred(pp_dac, attr_vector=[message1_str, message2_str], sk = sk_ca, nym_u = nym_u, k_prime = 3, proof_nym_u = proof_nym_u)
    (sigma, update_key, commitment_vector, opening_vector) = cred
    ## check the correctness of root credential
    assert (spseq_uc.verify(pp_sign, vk_ca, nym_u, commitment_vector, sigma)), ValueError("signature/credential is not correct")
    print()
    print("Creating a root credential, and checking if the credential is correct")

def test_issuing() -> None:
    """Test issuing/delegating a credential of user U to a user R."""
    (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
    ## create user key pair
    (usk_u, upk_u) = dac.user_keygen(pp_dac)

    ## create a proof of nym_u and root credential
    (nym_u, secret_nym_u, proof_nym_u) = dac.nym_gen(pp_dac, usk_u, upk_u)

    ## create a root cred for user  u
    cred = dac.issue_cred(pp_dac, attr_vector=[message1_str, message2_str], sk = sk_ca, nym_u = nym_u, k_prime = 3, proof_nym_u = proof_nym_u)

    ## issuing/delegating a credential of user U to a user R -------
    sub_mess_str = ["Insurance = 2 ", "Car type = BMW"]
    Attr_vector.append(sub_mess_str)

    ## generate key pair of user R
    (usk_R, upk_R) = dac.user_keygen(pp_dac)

    ## generate a nym for the upk_R with corresoing secret key of nym + proof of nym
    (nym_R, secret_nym_R, proof_nym_R) = dac.nym_gen(pp_dac, usk_R, upk_R)

    ## create a credential for new nym_R: delegateor P -> delegatee R
    cred_R_U = dac.delegator(pp_dac, cred, sub_mess_str, l=3, sk_u=secret_nym_u, proof_nym=proof_nym_R)
    (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi) = dac.delegatee(pp_dac, cred_R_U, sub_mess_str, secret_nym_R, nym_R)

    ## check the correctness of credential
    assert (spseq_uc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, sigma_prime)), ValueError("signature/credential is not correct")
    print()
    print("Issuing/delegating a credential of user U to a user R, and checking if the credential is correct")


def test_proof_cred() -> None:
    """Test proving a credential to verifiers."""
    ## create user key pair
    (usk, upk) = dac.user_keygen(pp_dac)

    ## create nym  and a proof for nym
    (nym_P, secret_nym_P, proof_nym_P) = dac.nym_gen(pp_dac, usk, upk)

    ## generate a credential
    cred = dac.issue_cred(pp_dac, attr_vector=Attr_vector, sk = sk_ca, nym_u = nym_P, k_prime = None, proof_nym_u = proof_nym_P)

    ## prepare a proof
    D = [SubList1_str, SubList2_str]
    proof = dac.proof_cred(pp_dac, nym_R = nym_P, aux_R = secret_nym_P, cred_R = cred, Attr=Attr_vector, D = D)

    ## check a proof
    assert (dac.verify_proof(pp_dac, proof, D)) , ValueError("the credential is not valid")
    print()
    print("proving a credential to verifiers, and checking if the proof is correct")
