//
// Created by PROMAR-PC on 7/22/2023.
//

#include "examples.h"

using namespace std;
using namespace seal;
// void info(string msg, Plaintext pt)
//{
//     cout << "\t\t**** " << msg << " ****" << endl;
//     cout << "\t\t" << pt.to_string() << endl;
//     cout << "\t\t\t\t****\n";
// }
void My_BFV_1()
{
    print_example_banner("My BFV 1");

    // Create an encryption parameter object
    EncryptionParameters parms(scheme_type::bfv);

    // The first parameter is the degree of the polynomial modulus
    size_t poly_modulus_dgr = 8192;
    parms.set_poly_modulus_degree(poly_modulus_dgr);

    // The second parameter is the ciphertext coefficient modulus
    // depending on the value of the polynomial modulus degree.
    // SEAL has a helper function to select the coeff_modulus
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_dgr));

    // The third parameter is the plaintext modulus, which is specific
    // to the BVF scheme.
    parms.set_plain_modulus(8192);

    // We construct a seal context object to wrap and validate the/
    // the properties of the parameters.
    SEALContext context(parms);

    // Print the parameters
    print_line(__LINE__);
    cout << "Encryption parameters:\n";
    print_parameters(context);

    // Check the validity of the parameters
    cout << "Parameter validation: " << context.parameter_error_message() << endl;
    cout << endl;

    cout << "~~~~~~ A naive way to compute 3(x^3+10)(x^2+2) ~~~~~~" << endl;

    // Create a key generator object
    KeyGenerator keygen(context);
    // Create the secret key
    SecretKey secretKey = keygen.secret_key();
    // Create a public key
    PublicKey publicKey;
    keygen.create_public_key(publicKey);

    // Create an encryptor object
    Encryptor encryptor(context, publicKey);
    // Create the Evaluator object to evaluate the computations
    Evaluator evaluator(context);
    // Create the decryptor object
    /*
     * Notice that if the client will run the decryption function,
     * it could violate the part of the Server Privacy definition,
     * since the client will need to know the parameters (context)
     * object.
     */
    Decryptor decryptor(context, secretKey);

    // Step (1): create a plaintext object for the integer 7
    uint64_t x = 7;
    Plaintext x_plain(uint64_to_hex_string(x));
    cout << "x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() << endl;

    // Step (2): encrypt x
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    // Check the size of the ciphertext
    cout << "Size of encrypted x = " << x_encrypted.size() << endl;

    // Check the noise budget in the ciphertext
    /*
     * Notice that the invariant_noise_budget function could be run only at the client
     * side, because it runs from the decryptor object, which requires the
     * secret key, which is assumed to be at the client side only. So, the
     * server will not be able to check the noise?!
     */
    cout << "Noise budget in fresh ciphertext: " << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;

    // Step (3): compute x^3 and add the plaintext 10
    Ciphertext x_cubic_plus_10;
    evaluator.square(x_encrypted, x_cubic_plus_10);
    evaluator.multiply(x_encrypted, x_cubic_plus_10, x_cubic_plus_10);
    Plaintext plain_10("A");
    evaluator.add_plain_inplace(x_cubic_plus_10, plain_10);

    // Check the size of the ciphertext
    cout << "Size of x_cubic_plus_10: " << x_cubic_plus_10.size() << endl;
    // Check the noise budget
    cout << "Noise budget in x_cubic_plus_10: " << decryptor.invariant_noise_budget(x_cubic_plus_10) << endl;

    // Step (4): compute x^2 + 2
    Ciphertext x_sq_plus_2;
    evaluator.square(x_encrypted, x_sq_plus_2);
    Plaintext plain_2("2");
    evaluator.add_plain_inplace(x_sq_plus_2, plain_2);

    // Step(5): multiply the three terms
    Ciphertext encrypted_res;
    Plaintext plain_3("3");
    evaluator.multiply_plain_inplace(x_cubic_plus_10, plain_3);
    evaluator.multiply(x_cubic_plus_10, x_sq_plus_2, encrypted_res);

    // Check the size of the encrypted result
    cout << "Size of the encrypted result: " << encrypted_res.size() << endl;
    // Check the noise budget
    cout << "Noise budget on the encrypted result: " << decryptor.invariant_noise_budget(encrypted_res) << endl;
    Plaintext res;
    decryptor.decrypt(encrypted_res, res);
    cout << "The result = " << res.to_string() << endl;
    /************************RELINEARIZATION**************************/

    cout << "\n~~~~~~~~~ A better way to calculate 3(x^3+10)(x^2+2) ~~~~~~~~~" << endl;

    // We need to apply relinearization after every multiplication
    cout << "Generate relinearization keys" << endl;
    RelinKeys relinKeys;
    keygen.create_relin_keys(relinKeys);

    // Step (1): compute x^2
    Ciphertext x_sqrd;
    evaluator.square(x_encrypted, x_sqrd);

    // Step (2): relinearize
    evaluator.relinearize_inplace(x_sqrd, relinKeys);

    // Step (3): compute x^2 * x = x^3
    evaluator.multiply(x_encrypted, x_sqrd, x_cubic_plus_10);

    // Step (4): Add 10
    evaluator.add_plain(x_cubic_plus_10, plain_10, x_cubic_plus_10);

    // Check the size of the ciphertext
    cout << "Size of x_cubic_plus_10: " << x_cubic_plus_10.size() << endl;
    // Check the noise budget
    cout << "Noise budget in x_cubic_plus_10 = " << decryptor.invariant_noise_budget(x_cubic_plus_10) << endl;

    Plaintext plain_res;

    // Step (5): compute x^2
    evaluator.square(x_encrypted, x_sq_plus_2);

    // Step (6): relinearize
    evaluator.relinearize_inplace(x_sq_plus_2, relinKeys);

    // Step (7): add 2
    evaluator.add_plain_inplace(x_sq_plus_2, plain_2);

    // Step (8): compute 3 * (x^3+10)
    evaluator.multiply_plain_inplace(x_cubic_plus_10, plain_3);

    // Step (9): relinearize
    evaluator.relinearize_inplace(x_cubic_plus_10, relinKeys);

    // Step (10): compute (3 * (x^3 + 10)) * (x^2 + 2)
    evaluator.multiply(x_cubic_plus_10, x_sq_plus_2, encrypted_res);

    // Step (11): relinearize
    evaluator.relinearize_inplace(encrypted_res, relinKeys);

    // Check the size of the encrypted result
    cout << "Size of the encrypted result: " << encrypted_res.size() << endl;
    // Check the noise budget
    cout << "Noise budget on the encrypted result: " << decryptor.invariant_noise_budget(encrypted_res) << endl;

    decryptor.decrypt(encrypted_res, plain_res);
    cout << "The result: " << plain_res.to_string() << endl;
}