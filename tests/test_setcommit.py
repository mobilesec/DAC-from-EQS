"""
This is a Test (and example of how it works) of set commitment and cross set commitment: set_commit.py
This file contains unit tests for the functions in set_commit.py
It tests the functions with different inputs and verifies that they produce the expected outputs.
"""

from core.set_commit import SetCommitment, CrossSetCommitment

## messagses
set_str = ["age = 30", "name = Alice ", "driver license = 12"]
set_str2 = ["Gender = male", "componey = XX ", "driver license type = B"]
## subsets of messagses
subset_str_1 = ["age = 30", "name = Alice "]
subset_str_2 = ["Gender = male", "componey = XX "]


def setup_module(module):
    print("__________Setup__test set commitment___________")
    global sc_scheme, cssc_scheme, pp
    # create SC and cssc objects
    sc_scheme = SetCommitment(max_cardinal =5)
    cssc_scheme = CrossSetCommitment(max_cardinal = 5)
    # create public parameters for SC schemes
    pp, alpha = sc_scheme.setup()

def test_commit_and_open():
    # create set commitment and opening for message set:  set_str
    (Commitment, O) = sc_scheme.commit_set(param_sc=pp, mess_set_str=set_str)
    # check if set commitment is correct with opening information
    assert(sc_scheme.open_set(pp, Commitment, O, set_str)), ValueError("set is not match with commit and opening info")

def test_open_verify_subset():
    # create set commitment and opening for message set:  set_str
    (commitment, O) = sc_scheme.commit_set(param_sc=pp, mess_set_str=set_str)
    # create witness for subset message subset str_1 due to commitment and opening
    witness = sc_scheme.open_subset(pp, set_str, O, subset_str_1)
    # check if subset is match with witness and commitment
    assert sc_scheme.verify_subset(pp, commitment, subset_str_1, witness), "subset is not match with witness"

def test_aggregate_verify_cross():
    """check aggregation of witnesses using cross set commitment scheme"""
    # create two set commitments for two sets set_str and set_str2
    C1, O1 = cssc_scheme.commit_set(pp, set_str)
    C2, O2 = cssc_scheme.commit_set(pp, set_str2)

    ## create a witness for each subset -> W1 and W2
    W1 = cssc_scheme.open_subset(pp, set_str, O1, subset_str_1)
    W2 = cssc_scheme.open_subset(pp, set_str2, O2, subset_str_2)

    ## aggregate all witnesses for a subset is correct-> proof
    proof = cssc_scheme.aggregate_cross(witness_vector=[W1, W2], commit_vector=[C1, C2])

    ## verification aggregated witnesses
    assert( cssc_scheme.verify_cross(pp, commit_vector=[C1, C2],
                                  subsets_vector_str=[subset_str_1, subset_str_2], proof=proof)), ValueError("verification aggegated witnesses fails")
