#include <iostream>

#include "seal/seal.h"
#include <ringsnark/zk_proof_systems/rinocchio/rinocchio.hpp>
#include <ringsnark/zk_proof_systems/groth16/groth16.hpp>

#include "poly_arith.h"
#include <ringsnark/seal/seal_ring.hpp>
#include <ringsnark/gadgetlib/protoboard.hpp>

using namespace std;
using namespace seal;

int main() {
    // Define the scheme type = bgv
    EncryptionParameters params(scheme_type::bgv);
    // Define the polynomial modulus degree = 2^11
    auto poly_modulus_degree = (size_t) pow(2, 11);
    params.set_poly_modulus_degree(poly_modulus_degree);
    // Initialize the coefficient modulus
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    // Initialize the plain modulus
    params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    // wrap the parameters in a context object
    SEALContext context(params);
    // Create a ring element object. This object, extends seal, defines how +, -, *, / are applied to a ring element
    typedef ringsnark::seal::RingElem R;
    // Create an Encoding Element object. This object is used for encoding parameters using seal primitives.
    typedef ringsnark::seal::EncodingElem E;
    // Attach the context object to the RingElem object
    R::set_context(context);
    E::set_context();

    // This line should return the polynomial modulus degree = 2^11
    const size_t N = context.get_context_data(context.first_parms_id())->parms().poly_modulus_degree();

    // Number of variables to hold
    const size_t n = 6;

    // An object of type RingElem to hold the variables, possibly for handling the R1CS system
    ringsnark::protoboard<R> pb;

    // A vector of values involved in the computation
    ringsnark::pb_variable_array<R> vars(n, ringsnark::pb_variable<R>());
    vars.allocate(pb, n, "x");
    pb.set_input_sizes(n - 1); // vars[4] is private, all other values are public

    // Set constraints
    // Inputs:  x0, x1, x2, x3
    // Outputs: x4
    // Private: x5
    // x5 := x2 * x3
    // x4 := (x0 + x1) * x5
    // So, this add_r1cs_constraint takes r1cs_constraint<R> objects: 1) the first operand, 2) the second operand
    // 3) the variable to hold the result of a * b
    pb.add_r1cs_constraint(ringsnark::r1cs_constraint<R>(vars[2], vars[3], vars[5]));
    pb.add_r1cs_constraint(ringsnark::r1cs_constraint<R>(vars[0] + vars[1], vars[5], vars[4]));

    // Set values
    // This is a vector of 6 RingElem elements
    vector<ringsnark::seal::RingElem> values(n);
    {
        /*
        Let N denote the poly_modulus_degree and T denote the plain_modulus. Batching
        allows the BFV plaintext polynomials to be viewed as 2-by-(N/2) matrices, with
        each element an integer modulo T.
         */
        auto encoder = BatchEncoder(context);
        // Get a pointer to NTT tables. NTT is the most efficient method for multiplying two polynomials
        // of high degree with integer coefficients
        auto tables = context.get_context_data(context.first_parms_id())->small_ntt_tables();

        vector<uint64_t> vs(N);
        Plaintext ptxt;
        vector<::polytools::SealPoly> polys(n, ::polytools::SealPoly(context));

        // Inputs
        vs[0] = 2;
        // encode the matrix values into the destination plaintext
        encoder.encode(vs, ptxt);
        // This a wrapper for underlying polynomials that make up plaintexts and ciphertexts in SEAL
        auto poly = polytools::SealPoly(context, ptxt, &(context.first_parms_id()));
        // Attach the ntt tables to the poly object
        poly.ntt_inplace(tables);
        // Now poly defines the value 2
        polys[0] = poly;
        // Represent poly as a ring ring element and append it the vector
        values[0] = ringsnark::seal::RingElem(poly);
//        values[0] = ringsnark::seal::RingElem(vs[0]);

        vs[1] = 3;
        encoder.encode(vs, ptxt);
        poly = polytools::SealPoly(context, ptxt, &(context.first_parms_id()));
        poly.ntt_inplace(tables);
        polys[1] = poly;
        values[1] = ringsnark::seal::RingElem(poly);
//        values[1] = ringsnark::seal::RingElem(vs[1]);

        vs[2] = 4;
        encoder.encode(vs, ptxt);
        poly = polytools::SealPoly(context, ptxt, &(context.first_parms_id()));
        poly.ntt_inplace(tables);
        polys[2] = poly;
        values[2] = ringsnark::seal::RingElem(poly);
//        values[2] = ringsnark::seal::RingElem(vs[2]);

        vs[3] = 5;
        encoder.encode(vs, ptxt);
        poly = polytools::SealPoly(context, ptxt, &(context.first_parms_id()));
        poly.ntt_inplace(tables);
        polys[3] = poly;
        values[3] = ringsnark::seal::RingElem(poly);
//        values[3] = ringsnark::seal::RingElem(vs[3]);

        // Intermediate values
        vs[5] = vs[2] * vs[3];
        poly = ::polytools::SealPoly(polys[2]);
        poly.multiply_inplace(polys[3]);
        polys[5] = poly;
        values[5] = ringsnark::seal::RingElem(poly);
//        values[5] = ringsnark::seal::RingElem(vs[5]);

        // Outputs
        vs[4] = (vs[0] + vs[1]) * vs[5];
        poly = ::polytools::SealPoly(polys[0]);
        poly.add_inplace(polys[1]);
        poly.multiply_inplace(polys[5]);
        polys[4] = poly;
        values[4] = ringsnark::seal::RingElem(poly);
//        values[4] = ringsnark::seal::RingElem(vs[4]);
    }
    for (size_t i = 0; i < n; i++) {
        pb.val(vars[i]) = values[i];
    }
    cout << "#Inputs\t" << pb.num_inputs() << endl;
    cout << "#Variables\t" << pb.num_variables() << endl;
    cout << "#Constraints\t" << pb.num_constraints() << endl;
    cout << "R1CS satisfied: " << std::boolalpha << pb.is_satisfied() << endl;
    cout << endl;

    {
        cout << "=== Rinocchio ===" << endl;
        // Get a public key and a verification key
        const auto keypair = ringsnark::rinocchio::generator<R, E>(pb.get_constraint_system());
        cout << "Size of pk:\t" << keypair.pk.size_in_bits() << " bits" << endl;
        cout << "Size of vk:\t" << keypair.vk.size_in_bits() << " bits" << endl;

        const auto proof = ringsnark::rinocchio::prover(keypair.pk, pb.primary_input(), pb.auxiliary_input());
        cout << "Size of proof:\t" << proof.size_in_bits() << " bits" << endl;

        const bool verif = ringsnark::rinocchio::verifier(keypair.vk, pb.primary_input(), proof);
        cout << "Verification passed: " << std::boolalpha << verif << endl;
    }
    {
        cout << "=============" << endl;
        cout << "=== RingGroth16 ===" << endl;
        const auto keypair = ringsnark::groth16::generator<R, E>(pb.get_constraint_system());
        cout << "Size of pk:\t" << keypair.pk.size_in_bits() << " bits" << endl;
        cout << "Size of vk:\t" << keypair.vk.size_in_bits() << " bits" << endl;

        const auto proof = ringsnark::groth16::prover(keypair.pk, pb.primary_input(), pb.auxiliary_input());
        cout << "Size of proof:\t" << proof.size_in_bits() << " bits" << endl;

        const bool verif = ringsnark::groth16::verifier(keypair.vk, pb.primary_input(), proof);
        cout << "Verification passed: " << std::boolalpha << verif << endl;
    }

// Omar added this to pause the program
int x; 
cout << "\n\nPause the program... "; // Type a number and press enter
cin >> x; // Get user input from the keyboard
}