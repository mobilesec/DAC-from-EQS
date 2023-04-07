"""
This is an implementation of Schnorr proof (non-interactive using FS heuristic), Schnorr interactive proof,  
and Damgard’s compiler for obtaining malicious-verifier interactive zero-knowledge proofs of knowledge
"""

from petlib.bn import Bn
from hashlib import sha256
from core.util import pedersen_setup, pedersen_committ, pedersen_dec, ec_sum


class ZKP_Schnorr_FS:
    """Schnorr proof (non-interactive using FS heuristic) of the statement ZK(x, m_1....m_n; h = g^x and h_1^m_1...h_n^m_n) and generilized version"""

    def __init__(self, group):
        self.G = group

    def setup(self):
        g = self.G.gen2()
        o = self.G.order()
        group = self.G
        params = (group, g, o)
        return params

    def challenge(self, elements):
        """Packages a challenge in a bijective way"""
        elem = [len(elements)] + elements
        elem_str = map(str, elem)
        elem_len = map(lambda x: "%s||%s" % (len(x), x), elem_str)
        state = "|".join(elem_len)
        H = sha256()
        H.update(state.encode("utf8"))
        return Bn.from_binary(H.digest())


    def non_interact_prove(self, params, stm, secret_wit):
        """Schnorr proof (non-interactive using FS heuristic)"""
        (G, g, o) = params
        if isinstance(stm, list) == True:
            w_list = [o.random() for i in range(len(stm))]
            W_list = [w_list[i] * g for i in range(len(w_list))]
            Anoncment = ec_sum(W_list)
            state = ['schnorr', g, stm, Anoncment.__hash__()]
            c = self.challenge(state) % o
            r = [(w_list[i] - c * secret_wit[i]) % o for i in range(len(secret_wit))]
            return (r, c)
        else:
            w = o.random()
            W = w * g
            state = ['schnorr', g, stm, W.__hash__()]
            c = self.challenge(state) % o
            # hash_c = challenge(state)
            # c = Bn.from_binary(hash_c) % o
            r = (w - c * secret_wit) % o
            return (r, c)


    def non_interact_verify(slef, params, stm, proof_list):
        """Verify the statement ZK(x ; h = g^x)"""
        (G, g, o) = params
        (r, c) = proof_list

        if isinstance(stm, list) == True:
            W_list = [r[i] * g + c * stm[i] for i in range(len(r))]
            Anoncment = ec_sum(W_list)
            state = ['schnorr', g, stm, Anoncment.__hash__()]
            hash = slef.challenge(state) % o
            return c == hash
        else:
            W = (r * g + c * stm)
            state = ['schnorr', g, stm, W.__hash__()]
            c2 = slef.challenge(state) % o
            return c == c2


class ZKP_Schnorr:
    """Schnorr (interactive) proof of the statement ZK(x ; h = g^x)"""

    def __init__(self, group):
        self.G = group
        self.params = self.setup(group)

    @staticmethod
    def setup(G):
        g = G.gen1()
        o = G.order()
        group = G
        params = (group, g, o)
        return params

    def challenge(self, elements):
        """Packages a challenge in a bijective way"""

        elem = [len(elements)] + elements
        elem_str = map(str, elem)
        elem_len = map(lambda x: "%s||%s" % (len(x), x), elem_str)
        state = "|".join(elem_len)
        H = sha256()
        H.update(state.encode("utf8"))
        return Bn.from_binary(H.digest())

    def announce(self):
        (G, g, o) = self.params
        w_random = o.random()
        W_element = w_random * g
        return (W_element, w_random)

    def response(self, challenge, announce_randomnes, stm, secret_wit):
        #G, g, o = params
        assert secret_wit * self.G.gen1() == stm
        res = (announce_randomnes + challenge * secret_wit) % self.G.order()
        return res

    def verify(self, challenge, announce_element, stm, response):
        """Verify the statement ZK(x ; h = g^x)"""
        (G, g, o) = self.params
        left_side = response * g
        right_side = (announce_element + challenge * stm)
        return left_side == right_side


class Damgard_Transfor(ZKP_Schnorr):
    """
     Damgard’s technique for obtaining malicious-verifier interactive zero-knowledge proofs of knowledge
    """
    def __init__(self, group):
        super().__init__(group)
        self.pp_pedersen = self.setup(group)

    @staticmethod
    def setup(group):
        (pp_pedersen, trapdoor) = pedersen_setup(group)
        return pp_pedersen

    def announce(self):
        (G, g, o, h) = self.pp_pedersen
        w_random = o.random()
        W_element = w_random * g
        pedersen_commit, (r,m) = pedersen_committ(self.pp_pedersen, w_random)
        pedersen_open = (r, m, W_element)
        return (pedersen_commit, pedersen_open)

    def verify(self, challenge, pedersen_open, pedersen_commit, stm, response):
        (G, g, o, h) = self.pp_pedersen
        (open_randomness, announce_randomnes, announce_element) = pedersen_open
        pedersen_open = (open_randomness, announce_randomnes)
        left_side = response * g
        right_side = (announce_element + challenge * stm)
        return left_side == right_side and pedersen_dec(self.pp_pedersen, pedersen_open, pedersen_commit)
