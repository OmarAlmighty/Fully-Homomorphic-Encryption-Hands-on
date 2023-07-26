#include "examples.h"

using namespace std;
using namespace seal;

void my_batch_encoder()
{
    print_example_banner("My Batch Encoder Example");

    // Step (1): define the parameters
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_mod_deg = 4096;
    parms.set_poly_modulus_degree(poly_mod_deg);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_mod_deg));

    // Step (2): To enable batching, we need to set the plain_modulus to
    // be a prime number congruent to 1 modulo 2*poly_modulus_degree.
    parms.set_plain_modulus(PlainModulus::Batching(poly_mod_deg, 20));

    // Step (3): wrap in a context object and validate the parameters
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // Check if batching is enabled
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    // Step (4): create the keygenerator object and the public key,
    // private key, and relinerarization keys
    KeyGenerator keygen(context);
    SecretKey secretKey = keygen.secret_key();
    PublicKey publicKey;
    keygen.create_public_key(publicKey);
    RelinKeys relinKeys;
    keygen.create_relin_keys(relinKeys);

    // Step (5): create the encryptor, evaluator, and decryptor
    Encryptor encryptor(context, publicKey);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secretKey);

    // Step (6): create a batch encoder object
    BatchEncoder batchEncoder(context);

    // The total number of batching slots equals the poly_mod_deg, N,
    // and these slots are organized into 2-by-(N/2) matrices that are
    // encrypted and computed on. Each slot contains an integer modulo
    // plain_modulus
    size_t slot_count = batchEncoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size" << row_size << endl;

    // Step (7): pass a flattened vector (the plaintext matrix)
    // to the batch_encoder
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size+1] = 5ULL;
    pod_matrix[row_size+2] = 6ULL;
    pod_matrix[row_size+3] = 7ULL;

    cout << "Input plaintext matrix: " << endl;
    print_matrix(pod_matrix, row_size);
    
    // Step (8): Encode the matrix into a plaintext polynomial
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix: "<< endl;
    batchEncoder.encode(pod_matrix, plain_matrix);

    // Step (9): Encrypt the encoded plaintext
    Ciphertext enc_mat;
    print_line(__LINE__);
    cout << "Encrypt plaintext matrix: "<<endl;
    encryptor.encrypt(plain_matrix, enc_mat);
    cout << "\t Noise budget in enc_mat: "<< decryptor.invariant_noise_budget(enc_mat) << endl;

    // Step (10): To demonstrate homomorphic operations, we create another plaintext
    // matrix with 8192 elements
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i & size_t(0x1))+1);
    }
    Plaintext plain_matrix2;
    batchEncoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2, row_size);

    // Step (11): compute (mat1 + mat2)^2
    print_line(__LINE__);
    cout << "Sum, square, relinearize" << endl;
    evaluator.add_plain_inplace(enc_mat, plain_matrix2);
    evaluator.square_inplace(enc_mat);
    evaluator.relinearize_inplace(enc_mat, relinKeys);

    // Get the noise budget
    cout <<"\t Noise budget in result: " << decryptor.invariant_noise_budget(enc_mat) << endl;

    // Step (12): decrypt and decompose the plaintext
    Plaintext plain_result;
    vector<uint64_t> pod_result;
    print_line(__LINE__);
    cout << "Decrypt and decode the result: "<< endl;
    decryptor.decrypt(enc_mat, plain_result);
    batchEncoder.decode(plain_result, pod_result);
    cout << "\tResult plaintext matrix" << endl;
    print_matrix(pod_result, row_size);
}

void my_ckks_encoder(){
    print_example_banner("My CKKS Encoder");

    // Step 1: Initialize the parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_mod_deg = 8192;
    parms.set_poly_modulus_degree(poly_mod_deg);
    parms.set_coeff_modulus(CoeffModulus::
                                Create(poly_mod_deg,
                                       {40, 40, 40, 40, 40}));

    // Step 2: Wrap the parameters in a context object
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // Step 3: Generate the keys
    KeyGenerator keyGen(context);
    auto secretKey = keyGen.secret_key();
    PublicKey publicKey;
    keyGen.create_public_key(publicKey);
    RelinKeys relinKeys;
    keyGen.create_relin_keys(relinKeys);

    // Step 4: Set up and encryptor, evaluator, and decryptor objects.
    Encryptor encryptor(context, publicKey);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secretKey);

    // Step 5: Creat a CKKSEncoder
    CKKSEncoder encoder(context);

    // In CKKS, the number of slots is poly_mod_deg / 2. Each slot
    // encodes one rela or complex number.
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: "<< slot_count << endl;

    // Step 6: Create a vector to encode. The CKKS encoder will pad
    // it with zeros.
    vector<double> input{0.0, 1.1, 2.2, 3.3};
    cout << "Input vector: "<< endl;
    print_vector(input);

    // Step 7: Define the scale parameter, which determines the bit-
    // precision of the encoding and the result.
    Plaintext plain;
    double scale = pow(2.0, 30);
    print_line(__LINE__);
    cout<< "Encode input vector" << endl;
    encoder.encode(input, scale, plain);

    // Step 8: Encrypt the encoded vector
    Ciphertext encrypted;
    print_line(__LINE__);
    cout << "Encypt input vector, quad, and relinearize" <<endl;
    encryptor.encrypt(plain, encrypted);

    // Step 9: Quad and relinearize
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relinKeys);
    evaluator.multiply_inplace(encrypted, encrypted);
    evaluator.relinearize_inplace(encrypted, relinKeys);

    // Check the scale value.
    cout << "\t Scale in cubic input: "<<encrypted.scale() << " (" << log2(encrypted.scale()) << " bits)"
         << endl;

    print_line(__LINE__);
    vector<double> output;
    cout << "Decrypt an decode" << endl;
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, output);
    print_vector(output);

}

void my_example_encoder(){
    print_example_banner("My Encoders Example");
    my_batch_encoder();
    my_ckks_encoder();
}