"""
This is a Test (and example of how it works) of SPSEQ-UC signiture: spseq_uc.py
This file contains unit tests for the functions in spseq_uc.py.
It tests the functions with different inputs and verifies that they produce the expected outputs.
"""

from core.spseq_uc import EQC_Sign

message1_str = ["age = 30", "name = Alice ", "driver license = 12"]
message2_str = ["genther = male", "componey = XX ", "driver license type = B"]
message3_str = ["Insurance = 2 ", "Car type = BMW"]

def setup_module(module):
    print()
    print("__________Setup___Test SPEQ-UC Signature________")
    global pp, sign_scheme
    # create a signature object
    sign_scheme =EQC_Sign(max_cardinal= 5)
    # create public parameters with a trapdoor alpha
    pp, alpha = sign_scheme.setup()

def test_sign():
    """Generate a signature and verify it"""

    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    # create a signature sigma for user pk_u, without update_key
    (sigma, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector = [message1_str,message2_str])

    # verify sigma
    assert(sign_scheme.verify(pp, vk, pk_u, commitment_vector, sigma)), ValueError("signiture is not correct")
    print()
    print("Generate a signature and verify it")

def test_changerep():
    """Generate a signature, run changrep function and verify it"""
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp

    # pick randomness mu and psi
    mu, psi = group.order().random(), group.order().random()

    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    # create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2 and aslo output update_key for k_prime = 4, allow adding 2 more commitments for rang k = 2 to k' = 4
    (sigma, update_key, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector=[message1_str, message2_str], k_prime=4)

    # run changerep function (without randomizing update_key) to randomize the sign, pk_u and commitment vector
    (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, rndmz_pk_u, chi) = sign_scheme.change_rep(pp, vk, pk_u, commitment_vector, opening_vector, sigma, mu, psi, B=False, update_key=None)

    # check the randomized signature is valid for the new values
    assert (sign_scheme.verify(pp, vk, rndmz_pk_u, rndmz_commitment_vector, sigma_prime)), ValueError("CahngeRep signiture is not correct")
    print()
    print("Generate a signature, run changrep function and verify if output of changrep (randomized sign) is correct")

def test_changerep_uk():
    """Generate a signature, run changrep function using update_key, randomize update_key (uk) and verify it"""
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp

    # pick randomness mu and psi
    mu, psi = group.order().random(), group.order().random()

    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    # create a signature for pk_u, (C1, C2) related to (message1_str, message2_str) with k = 2 and aslo output update_key for k_prime = 4, allow adding 2 more commitments for rang k = 2 to k' = 4
    (sigma, update_key, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector=[message1_str, message2_str], k_prime=4)

    # run changerep function (with randomizing update_key) to randomize the sign, pk_u, update_key and commitment vector
    (sigma_prime, rndmz_update_key, rndmz_commitment_vector, rndmz_opening_vector, rndmz_pk_u, chi)=sign_scheme.change_rep(pp, vk, pk_u, commitment_vector, opening_vector, sigma, mu, psi, B=True, update_key=update_key)

    # check this new signature
    assert (sign_scheme.verify(pp, vk, rndmz_pk_u, rndmz_commitment_vector, sigma_prime)), ValueError("CahngeRep signature with update key update_key is not correct")
    print()
    print("Generate a signature, run changrep function using update_key, randomize signature and update_key (uk) and verify all")

def test_changerel_from_sign():
    """Generate a signature, run changrel function one the signature, add one additional commitment using update_key (uk) and verify it"""
    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    # create a signature for pk_u on (C1, C2) related to (message1_str, message2_str)) and aslo output update_key for k_prime = 4, allow adding 2 more commitments like C3 and C4
    (sigma, update_key, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector=[message1_str, message2_str], k_prime=4)

    # run changerel function (with update_key) to add commitment C3 (for message3_str) to the sign where index L = 3
    (Sigma_tilde, Commitment_L, Opening_L, Commitment_vector_new, Opening_vector_new) =sign_scheme.change_rel(pp, message3_str, 3, sigma, commitment_vector, opening_vector, update_key)

    # check if the new signature is valid for C1, C2, C3 where C3 is the new commitment
    assert (sign_scheme.verify(pp, vk, pk_u, Commitment_vector_new, Sigma_tilde)), ValueError("CahngeRel Signiture from Sign is not correct")
    print()
    print("Generate a signature, run changrel function, which adds one additional commitment using update_key (uk), and verify the new signature with the extended commitment")


def test_changerel_from_rep():
    """run changrel on the signature that is coming from cgangrep (that is already randomized) and verify it"""
    (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp
    # pick randomness mu and psi
    mu, psi = group.order().random(), group.order().random()

    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    # create a signature for pk_u on (C1, C2) related to (message1_str, message2_str)) and output update_key as well
    (sigma, update_key, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector=[message1_str, message2_str], k_prime=4)

    # run changrep to randomize the signature and commitment vector, pk_u, and update_key
    (sigma_prime, rndmz_update_key, rndmz_commitment_vector, rndmz_opening_vector, rndmz_pk_u, chi) = sign_scheme.change_rep(pp, vk, pk_u, commitment_vector, opening_vector, sigma, mu, psi, B=True, update_key=update_key)

    # run changerel on the randomized sign using randomized update_key to add commitment C3 (for message3_str) to this new sign
    (Sigma_tilde, Commitment_L, Opening_L, Commitment_vector_new, Opening_vector_new) =sign_scheme.change_rel(pp, message3_str, 3, sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, rndmz_update_key, mu)

    # check if the new signature is valid for C1, C2, C3 where C3 is the new commitment
    assert(sign_scheme.verify(pp, vk, rndmz_pk_u, Commitment_vector_new, Sigma_tilde)), ValueError("CahngeRel on signature from Rep is not correct")
    print()
    print("Run changrel on the signature that is coming from cgangrep (that is already randomized) and verify it")

def test_convert():
    """run convert protocol (send_convert_sig, receive_convert_sig) to switch a pk_u to new pk_u and verify it"""
    # create a signing keys for 10 messagses
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)

    # create a user key pair
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

    # create a signature
    (sigma, update_key, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector=[message1_str, message2_str], k_prime=4)

    # create a new user key pair
    (sk_new, PK_u_new) = sign_scheme.user_keygen(pp)

    # run convert protocol between sender and receiver to create signature for new pk
    sigma_orpha = sign_scheme.send_convert_sig(vk, sk_u, sigma)
    sigma_new = sign_scheme.receive_convert_sig(vk, sk_new, sigma_orpha)

    # check if the new signature is valid for pk_new
    assert(sign_scheme.verify(pp, vk, PK_u_new, commitment_vector, sigma_new))
    print()
    print("run convert protocol (send_convert_sig, receive_convert_sig) to switch a pk_u to new pk_u and verify the new signature for new pk_u it")
