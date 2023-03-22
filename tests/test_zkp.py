"""
This is a Test (and example of how it works) of ZKP protocols
"""

from bplib.bp import BpGroup
from core.zkp import ZKP_Schnorr, ZKP_Schnorr_FS, Damgard_Transfor

def setup_module(module):
    print("__________Setup__Test ZKP___________")
    global BG
    global pp_pedersen
    global Schnorr
    global Schnorr_FS
    global pp_schnorr
    global Damgard
    global pp

    BG = BpGroup()
    Schnorr = ZKP_Schnorr(BG)
    Damgard = Damgard_Transfor(BG)
    Schnorr_FS = ZKP_Schnorr_FS(BG)
    pp_schnorr = Schnorr_FS.setup()
    pp = Schnorr.params
    pp_pedersen = Damgard.pp_pedersen

def test_non_interact_prove():
    (G, g, o) = pp_schnorr

    # create a single statement
    x = o.random()
    h = x *g
    print(type(h))

    # create a list statement
    secrets = [o.random() for i in range(5)]
    stm = [secrets[i] * g for i in range(len(secrets))]
    proof_list = Schnorr_FS.non_interact_prove(pp_schnorr, stm, secrets)
    # verfiy the proof for statement
    assert (Schnorr_FS.non_interact_verify(pp_schnorr, stm, proof_list))

    # create a proof for statement
    proof = Schnorr_FS.non_interact_prove(pp_schnorr, h, x)
    # verfiy the proof for statement
    assert (Schnorr_FS.non_interact_verify(pp_schnorr, h, proof))


def test_interact_prove():
    (G, g, o) = pp

    # create a statement
    x = o.random()
    stm = x * g

    # prover creates an announcement -> W = g^w
    announce = Schnorr.announce()
    (W_element, w_random) = announce

    # verifier creates a challenge
    state = ['schnorr', g, stm, W_element.__hash__()]
    challenge = Schnorr.challenge(state)

    # prover creates a respoonse (or proof)
    response = Schnorr.response(challenge, w_random, stm, x)

    # verfiy check the proof for statement
    assert(Schnorr.verify(challenge, W_element, stm, response))


def test_Damgard_Transfor():
    (G, g, o, h) = pp_pedersen

    # create a statement
    x = o.random()
    h = x * g

    # create an announcement
    (pedersen_commit, pedersen_open) = Damgard.announce()
    (open_randomness, announce_randomnes, announce_element) = pedersen_open

    # get s challenge
    state = ['schnorr', g, h, pedersen_commit.__hash__()]
    challenge = Damgard.challenge(state)

    # prover creates a respoonse (or proof)
    response = Damgard.response(challenge, announce_randomnes, h, x)

    # verfiy the proof for statement
    assert(Damgard.verify(challenge, pedersen_open, pedersen_commit, h, response))
