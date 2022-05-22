/* Author: SukJoon Oh
 * Test Environment: 
 *  - Manjaro Quonos 21.2, Native Desktop
 *      g++ (GCC) 11.2.0,
 *      OpenSSL 1.1.1n 
 *      (comes default in coreutils, no additional installation needed)
 *  - Ubuntu 20.04.4 LTS (Focal Fossa), VM Instance
 *      g++ (GCC) 9.4.0
 *      OpenSSL 1.1.1f
 *      libssl-dev needed, not default in RAW Ubuntu 20.04.
 *          run: apt install libssl-dev
 * Compilation Option: -lssl -lcrypto
 *      Refer to Makefile for more information.
 * Legal Stuff: None
 */

/* Every API information can be found in the official document:
 *  https://www.openssl.org, specifically https://www.openssl.org/docs/man1.1.1/man3/
 */

#ifdef __PRINT
#include <iostream>
#endif

#ifndef __OPENSSL
#define __OPENSSL
#endif

#include <string>
#include <cstring>

#include "./schnorr.h"
#define __BN_MODIFIABLE__(X) const_cast<BIGNUM*>((X))


/* 
 * BigNumberWrapper Actions */
EE488::BigNumberWrapper::BigNumberWrapper() : actor(BN_new()) {}
EE488::BigNumberWrapper::~BigNumberWrapper() {

    // Free all actors
    if (actor != nullptr)
        BN_free(actor);
}


EE488::BigNumberWrapper::BigNumberWrapper(const BigNumberWrapper& arg_bnw) {

    // Free all actors
    if (arg_bnw.actor != nullptr)
        BN_copy(this->actor, arg_bnw.actor);
}


EE488::BigNumberWrapper::BigNumberWrapper(const BigNumberWrapper&& arg_bnw) {

    // Free all actors
    if (arg_bnw.actor != nullptr)
        BN_copy(this->actor, arg_bnw.actor);
}


EE488::BigNumberWrapper& 
EE488::BigNumberWrapper::operator =(const BigNumberWrapper& arg_bnw) {

    if (arg_bnw.actor != nullptr)
        BN_copy(this->actor, arg_bnw.actor);

    return *this;
};


/* 
 * BigNumberManager Actions */
EE488::BigNumberManager::BigNumberManager() {
    asset = std::vector<bnw_t>(NPARAMS);

    for (auto& elem: asset)
        BN_zero(elem.actor); // Registers the asset.
};



EE488::BigNumberManager::BigNumberManager(std::vector<bnw_t>* arg_asset) {

    // Copies assets
    // Yet impl'd
};



/* Arguments are copied to the member asset. */
void EE488::BigNumberManager::set_asset(BIGNUM* arg_num, int arg_idx) {
    BN_copy(asset.at(arg_idx).actor, arg_num);
}



void EE488::BigNumberManager::set_keys(BIGNUM* arg_pk, BIGNUM* arg_sk) {
    BN_copy(asset.at(BN_PK).actor, arg_pk);
    BN_copy(asset.at(BN_SK).actor, arg_sk);
}



const BIGNUM* EE488::BigNumberManager::get_asset(int arg_idx) {
    return asset.at(arg_idx).actor;
}



void EE488::BigNumberManager::reset_asset() {

    for (auto& elem: asset)
        BN_clear(elem.actor); // Registers the asset.
};



void EE488::SchnorrSignature::console_msg(const char* arg_fname, const char* arg_msg) {

#ifdef __PRINT
    std::cout << "\t" << arg_fname << ":: " << arg_msg;
#endif
    ;
};



void EE488::SchnorrSignature::console_msg(const char* arg_fname, const std::string& arg_str) {
    this->console_msg(arg_fname, arg_str.c_str());
};



void EE488::SchnorrSignature::console_msgn(const char* arg_fname, const char* arg_msg) {

#ifdef __PRINT
    std::cout << "\t" << arg_fname << ":: " << arg_msg << std::endl;
#endif
    ;
};


void EE488::SchnorrSignature::console_msgn(const char* arg_fname, const std::string& arg_str) {
    this->console_msgn(arg_fname, arg_str.c_str());
};


/*
 * do_tkeygen
 */
int EE488::SchnorrSignature::do_tkeygen(const int arg_l, const int arg_n) {

    /* https://www.openssl.org/docs/man1.1.1/man3/BN_generate_prime.html
     * If add is not NULL, the prime will fulfill the condition 
     * p % add == rem (p % add == 1 if rem == NULL) in order to suit a given generator.
     */

    console_msgn(__FUNCTION__, "Toy key generation start.");
    
    if (!BN_generate_prime_ex(
        __BN_MODIFIABLE__(manager.get_asset(BN_Q)),
        arg_n, 
        false,      // Safe prime?
        NULL,       // ADD
        NULL,       // REM
        NULL        // CALLBACK
        )) {
        
        console_msg(__FUNCTION__, "Error, Generation of Q failed.");
    }

    if (!BN_generate_prime_ex(
        __BN_MODIFIABLE__(manager.get_asset(BN_P)),
        arg_l, 
        false,                      // Safe prime?
        manager.get_asset(BN_Q),    // ADD
        NULL,                       // REM
        NULL                        // CALLBACK
        )) {
        
        console_msg(__FUNCTION__, "Error, Generation of P failed.");
    }


#ifdef __PRINT
    console_msg(__FUNCTION__, "Generated P:");
    BN_print_fp(
        stdout, 
        manager.get_asset(BN_P)
        );

    std::cout << std::endl;
#endif

#ifdef __PRINT
    console_msg(__FUNCTION__, "Generated Q:");
    BN_print_fp(
        stdout, 
        manager.get_asset(BN_Q)
        );

    std::cout << std::endl;
#endif

    /* P and Q are generated, --till here. */

    /* Generate Parameter g */
    {   
        BIGNUM* tbn_h   = BN_new();
        BIGNUM* tbn_p_1 = BN_new();
        BIGNUM* tbn_div = BN_new();

        BN_CTX* tbn_ctx = BN_CTX_new();

        BN_set_word(tbn_h, 2);  // Init to 2.

        BN_copy(tbn_p_1, manager.get_asset(BN_P));  // tbn_p_1 = BN_P
        BN_sub_word(tbn_p_1, 1);                    // tbn_p_1 = BN_P - 1

        BN_div(tbn_div, NULL, tbn_p_1, manager.get_asset(BN_Q), tbn_ctx);

        // Get random number 'g'
        // Refered to, https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
        do {

            BN_mod_exp(                     // g = h^k mod p
                __BN_MODIFIABLE__(manager.get_asset(BN_G)),                        
                                            // Save to, g
                tbn_h,                      // h
                tbn_div,                    // p - 1 / q
                manager.get_asset(BN_P),    // p
                tbn_ctx);  

            BN_add_word(tbn_h, 1);          // Incr tbn_h by one.

            console_msg(__FUNCTION__, "Test g: ");

        } while (BN_is_one(
            manager.get_asset(BN_G)
        ));

        BN_free(tbn_h), BN_free(tbn_p_1), BN_free(tbn_div);
        BN_CTX_free(tbn_ctx);

        console_msgn(__FUNCTION__, "Generated g.");
    }

    /* Generate Secrey Key x */
    /*  If zero, generate again. 
     */
    do {
        BN_rand_range(
            __BN_MODIFIABLE__(manager.get_asset(BN_SK)), 
            manager.get_asset(BN_Q));

    } while (BN_is_zero(
        manager.get_asset(BN_SK)
    ));


    /* Generate Public Key */
    {
        BN_CTX* tbn_ctx = BN_CTX_new();

        BN_mod_exp(
            __BN_MODIFIABLE__(manager.get_asset(BN_PK)), 
            manager.get_asset(BN_G),
            manager.get_asset(BN_SK),
            manager.get_asset(BN_P),
            tbn_ctx
        );

        BN_CTX_free(tbn_ctx);
    }

    console_msgn(__FUNCTION__, "Toy key generation end.");
    pk_ready = sk_ready = true;

    return 0;
}


/*
 * do_rkeygen
 */
int EE488::SchnorrSignature::do_rkeygen(const int arg_bits) {
    
    DSA* dsa_key = DSA_new();

    /* Refer to,
     * https://www.openssl.org/docs/man1.1.1/man3/DSA_generate_parameters_ex.html
     * https://www.openssl.org/docs/man1.1.1/man3/BN_generate_prime.html
     * DSA_generate_parameters_ex : Creates two primes, p and q and a generator g.
     *      The results are stored in the DSA container, dsa_key.
     */
    DSA_generate_parameters_ex(
        dsa_key,    // DSA, stores the result in here.
        arg_bits,   // BITS, length of primes p and q and a generator g
        NULL,       // SEED, when given null, the primes will be generated at random.
        0,          // SEED_LEN, when it is less then len(q), error is returned.
        NULL,       // COUNTER_RET, iteration count.
        NULL,       // H_RET, counter used for finding a generator.
        NULL        // CALLBACK, feedback about the progress of the key generation
    );

    if (!DSA_generate_key(dsa_key)) {
        console_msgn(__FUNCTION__, "ERROR, DSA_generate_key");
        return -1;
    }
    
    /* Setting three parameters, p q g */
    manager.set_asset(__BN_MODIFIABLE__(DSA_get0_p(dsa_key)), BN_P);
    manager.set_asset(__BN_MODIFIABLE__(DSA_get0_q(dsa_key)), BN_Q);
    manager.set_asset(__BN_MODIFIABLE__(DSA_get0_g(dsa_key)), BN_G);

    /* Official API returns it as const BIGNUM. 
     *  Safe to convert, since no modifications are done.
     */

    manager.set_keys(
        __BN_MODIFIABLE__(DSA_get0_pub_key(dsa_key)),
        __BN_MODIFIABLE__(DSA_get0_priv_key(dsa_key))
    );

    /* Record to file when __PRINT is enabled.
     *  Best for debugging purpose.
     */
    {

#ifdef __PRINT
        console_msgn(__FUNCTION__, "Writing to log...");

        FILE* fp = std::fopen("./params.log", "w");

        std::fprintf(fp, "p\t"),    BN_print_fp(fp, manager.get_asset(BN_P));
        std::fprintf(fp, "\nq\t"),  BN_print_fp(fp, manager.get_asset(BN_Q));
        std::fprintf(fp, "\ng\t"),  BN_print_fp(fp, manager.get_asset(BN_G));
        std::fprintf(fp, "\npk\t"),  BN_print_fp(fp, manager.get_asset(BN_PK));
        std::fprintf(fp, "\nsk\t"),  BN_print_fp(fp, manager.get_asset(BN_SK));
        std::fprintf(fp, "\n");

        std::fclose(fp);

        console_msgn(__FUNCTION__, "Done.");
#endif

    }

    /* OpenSSL's API is only used for generating keys.
     * No more use further. Thus just delete the object.
     */
    DSA_free(dsa_key);  

    pk_ready = sk_ready = true; // Now the key is ready to go.

    return 0;
}



/*
 * do_regmsg
 */
int EE488::SchnorrSignature::do_regmsg(const char* arg_pmsg) {
    std::strcpy(reinterpret_cast<char *>(mstr), arg_pmsg);

    console_msgn(__FUNCTION__, "Registered string:");
    console_msgn(__FUNCTION__, reinterpret_cast<char *>(mstr));

    msg_ready = true;// Now the original message is ready to go.
    return 0;
}


/*
 * do_rhash
 */
BIGNUM* EE488::SchnorrSignature::do_rhash() {

    return this->do_rhash(reinterpret_cast<char *>(this->mstr));
}


BIGNUM* EE488::SchnorrSignature::do_rhash(const char* arg_str) {
    
    return this->do_rhash(std::string(arg_str));
}


BIGNUM* EE488::SchnorrSignature::do_rhash(std::string arg_str) {

    SHA256_CTX sha_context; // Local

    if (!SHA256_Init(&sha_context)) {
        console_msgn(__FUNCTION__, "Error, SHA256_Init");
        return nullptr;
    }

    if(!SHA256_Update(&sha_context, arg_str.c_str(), arg_str.length())) {
        console_msgn(__FUNCTION__, "Error, SHA256_Update");
        return nullptr;
    }

	if(!SHA256_Final(sha_digest, &sha_context)) {
        console_msgn(__FUNCTION__, "Error, SHA256_Final");
        return nullptr;
    }

    /* Register the hash value. */
    
    BIGNUM* hash_val = BN_new();
    // __BN_MODIFIABLE__(manager.get_asset(BN_E));

    /* Conversion */
    BN_bin2bn(sha_digest, sizeof(sha_digest), hash_val);
    
    console_msg(__FUNCTION__, "SHA256 hashed: ");
#ifdef __PRINT 
    BN_print_fp(stdout, hash_val);
    std::cout << std::endl;

    FILE* fp = std::fopen("./hash.log", "w");
    std::fprintf(fp, "Given string\t");
    std::fprintf(fp, arg_str.c_str());
    std::fprintf(fp, "\nHashed\t"), BN_print_fp(fp, hash_val);
    std::fclose(fp);
#endif


    return hash_val;
}


/*
 * do_thash
 */
BIGNUM* EE488::SchnorrSignature::do_thash(const int arg_bitn) {

    return this->do_thash(arg_bitn, reinterpret_cast<char *>(this->mstr));
}


BIGNUM* EE488::SchnorrSignature::do_thash(const int arg_bitn, const char* arg_str) {
    
    return this->do_thash(arg_bitn, std::string(arg_str));
}



BIGNUM* EE488::SchnorrSignature::do_thash(const int arg_bitn, std::string arg_str) {

    SHA256_CTX sha_context; // Local

    /* Almost identical to do_rhash */
    if (!SHA256_Init(&sha_context)) {
        console_msgn(__FUNCTION__, "Error, SHA256_Init");
        return nullptr;
    }

    if(!SHA256_Update(&sha_context, arg_str.c_str(), arg_str.length())) {
        console_msgn(__FUNCTION__, "Error, SHA256_Update");
        return nullptr;
    }

	if(!SHA256_Final(sha_digest, &sha_context)) {
        console_msgn(__FUNCTION__, "Error, SHA256_Final");
        return nullptr;
    }

    /* Register the hash value. */

    BIGNUM* hash_val = BN_new();
    // __BN_MODIFIABLE__(manager.get_asset(BN_E));

    /* Conversion */
    BN_bin2bn(sha_digest, sizeof(sha_digest), hash_val);

    /* Toy case, use only leftmost arg_bitn bits.*/
    console_msg(__FUNCTION__, "SHA256 hashed: ");
#ifdef __PRINT 
    BN_print_fp(stdout, hash_val);
    std::cout << std::endl;
#endif

    /* Cut! and Re-register */
    BN_rshift(
        hash_val, hash_val, arg_bitn
    );
    
    console_msg(__FUNCTION__, "SHA256 cut-hashed: ");
#ifdef __PRINT 
    BN_print_fp(stdout, hash_val);
    std::cout << std::endl;
#endif

    return hash_val;
}


/*
 * do_sign
 */
int EE488::SchnorrSignature::do_sign(const int arg_bitn) {
    
    if (!is_sk_ready() || !is_msg_ready()) {
        console_msgn(__FUNCTION__, "Error, key/msg is not ready.");
        return -1;
    }

    {
        BIGNUM* tbn = BN_new();         // Temporary big number.
        BN_CTX* tbn_ctx = BN_CTX_new();
            /* Big number context is a temporary variable
             * used in the library.
             */

        BN_rand_range(                  // Random number
            tbn,                        // Save to, tbn
            manager.get_asset(BN_Q));

        manager.set_asset(tbn, BN_K);   // Set k.
        BN_clear(tbn);                  // reset the temporary value.

        /* 
         * Signing message, 
         * for randomly chosen k(tbn, BN_K), r = g^k mod p where:
         * r: BN_R
         * g: BN_G
         * p: BN_P
         */
        BN_mod_exp(                     // r = g^k mod p
            tbn,                        // Save to, r
            manager.get_asset(BN_G),    // g
            manager.get_asset(BN_K),    // k
            manager.get_asset(BN_P),    // p
            tbn_ctx);  

        /* Set BN_R */
        manager.set_asset(tbn, BN_R);
        BN_clear(tbn);

        /* Second round.
         */
        unsigned char arr_r2bin[512] = { 0, };

        BN_bn2bin(manager.get_asset(BN_R), arr_r2bin);

        std::strcat(
            reinterpret_cast<char*>(mstr), 
            reinterpret_cast<char*>(arr_r2bin)
        );

        /* Run hashing */
        BIGNUM* hash_value = do_hash(arg_bitn);

        BN_mod_mul(
            tbn,                        // Save to, r
            manager.get_asset(BN_SK),   // secret key
            hash_value,                 // hashed?
            manager.get_asset(BN_Q),    // q
            tbn_ctx
        );

        BN_mod_add(
            __BN_MODIFIABLE__(manager.get_asset(BN_S)),
            tbn,
            manager.get_asset(BN_K),
            manager.get_asset(BN_Q),
            tbn_ctx
        );
        
        manager.set_asset(hash_value, BN_E);
        BN_free(hash_value);

        console_msg(__FUNCTION__, "Signed [S]: ");
#ifdef __PRINT
        BN_print_fp(stdout, manager.get_asset(BN_S)), 
        std::cout << "\n";
#endif

        console_msg(__FUNCTION__, "Signed [E]: ");
#ifdef __PRINT
        BN_print_fp(stdout, manager.get_asset(BN_E)), 
        std::cout << "\n";
#endif

        /* Remove temporary values */
        BN_free(tbn);
        BN_CTX_free(tbn_ctx);
    }

    sign_ready = true;

    console_msgn(__FUNCTION__, "Done.");
    return 0;
}



/*
 * do_verify
 */
int EE488::SchnorrSignature::do_verify(const int arg_bitn) {

    int ret_code = 0;

    if (
        !is_msg_ready() ||
        !is_pk_ready()  ||  // All threes should be ready.
        !is_sign_ready()
        ) {

        console_msgn(__FUNCTION__, "Error, key/msg is not ready.");
        return -1;
    }

        console_msg(__FUNCTION__, "Current signed [S]: ");
#ifdef __PRINT
        BN_print_fp(stdout, manager.get_asset(BN_S)), 
        std::cout << "\n";
#endif

        console_msg(__FUNCTION__, "Current signed [E]: ");
#ifdef __PRINT
        BN_print_fp(stdout, manager.get_asset(BN_E)), 
        std::cout << "\n";
#endif

    {
        BIGNUM* tbn_1 = BN_new();           // Temporary Big Number
        BIGNUM* tbn_2 = BN_new();           // Temporary Big Number
        BIGNUM* ipk = BN_new();             // Inverse of Public Key
        BN_CTX* tbn_ctx = BN_CTX_new();     // Temporary BN Context

        /* 
         * tbn_1 = g^s
         */
        BN_mod_exp(
            tbn_1,                          // Return value lies here.
            manager.get_asset(BN_G),        // g
            manager.get_asset(BN_S),        // s
            manager.get_asset(BN_P),        // p
            tbn_ctx);

        /*
         * ipk = {PK^{-1}}
         */
        BN_mod_inverse(
            ipk,                            // Return value lies here.
            manager.get_asset(BN_PK),       // public key
            manager.get_asset(BN_P),        // p
            tbn_ctx
        );
        
        /*
         * tbn_2 = {PK^{-1}}^e
         */
        BN_mod_exp(
            tbn_2,                          // Return value lies here.
            ipk,                            // Inverse of public key
            manager.get_asset(BN_E),        // public key
            manager.get_asset(BN_P),        // e
            tbn_ctx
        );

        /*
         * tbn_1 * tbn_2 = g^s * {PK^{-1}}^e
         */
        BN_mod_mul(
            __BN_MODIFIABLE__(manager.get_asset(BN_V)),
                                            // v
            tbn_1,                          // g^s
            tbn_2,                          // {PK^{-1}}^e
            manager.get_asset(BN_P),        // p
            tbn_ctx                     
        );

        /* From here, follows same with do_sign()
         */

        unsigned char arr_v2bin[512] = { 0, };

        BN_bn2bin(
            manager.get_asset(BN_V),        // From?
            arr_v2bin                       // Destination
        );

        std::strcat(
            reinterpret_cast<char*>(mstr),  
            reinterpret_cast<char*>(arr_v2bin)
        );

        BN_free(tbn_1), BN_free(tbn_2);
    }

    BIGNUM* hash_value = do_hash(arg_bitn);
    manager.set_asset(hash_value, BN_NE);

    BN_bin2bn(
        get_sha_digest(),
        sizeof(sha_digest),
        __BN_MODIFIABLE__(manager.get_asset(BN_NE))
        );
    
    /* Is toy? */
    if (toy_enable) {
        BN_rshift(
            __BN_MODIFIABLE__(manager.get_asset(BN_NE)), 
            manager.get_asset(BN_NE), 
            arg_bitn
        );
    }

    /* Prints out. */
        console_msg(__FUNCTION__, "New [E]: ");
#ifdef __PRINT
        BN_print_fp(stdout, manager.get_asset(BN_NE)), 
        std::cout << "\n";
#endif

        console_msg(__FUNCTION__, "Old [E]: ");
#ifdef __PRINT
        BN_print_fp(stdout, manager.get_asset(BN_E)), 
        std::cout << "\n";
#endif

    ret_code = BN_cmp(
        manager.get_asset(BN_E),
        manager.get_asset(BN_NE)
        );

    BN_free(hash_value);

    return ret_code;
}


/*
 * do_reset
 */
int EE488::SchnorrSignature::do_reset() {

    console_msgn(__FUNCTION__, "Reset.");

    manager.reset_asset(); // Clear all containers
    toy_enable = pk_ready = sk_ready = msg_ready = sign_ready = false;

    return 0;
}



