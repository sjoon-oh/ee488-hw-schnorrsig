/* Author: SukJoon Oh
 * Environment: 
 *      Manjaro Quonos 21.2, 
 *      g++ (GCC) 11.2.0,
 *      OpenSSL 1.1.1n (comes default in coreutils)
 * Compilation Option: -lssl -lcrypto
 *      Refer to Makefile for more information.
 * Legal Stuff: None
 */

/* Every API information can be found in the official document:
 *  https://www.openssl.org, specifically https://www.openssl.org/docs/man1.1.1/man3/
 */
#define __PRINT
#ifdef __PRINT
#include <chrono>
#include <iostream>
#endif

#ifndef __OPENSSL
#define __OPENSSL
#endif

#include <string>
#include <cstring>

#include "./schnorr.h"

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



void EE488::BigNumberManager::set_asset(BIGNUM* arg_num, int arg_idx) {
    /* Arguments are copied to the member asset.
     */
    
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



/*
 * do_keygen_t
 */
int EE488::SchnorrSignature::do_keygen_t(const int arg_l, const int arg_n) {

#ifdef __PRINT
    auto clk_start = std::chrono::steady_clock::now();
#endif

    BN_generate_prime_ex(
        const_cast<BIGNUM*>(manager.get_asset(BN_P)),
        arg_l, 
        false,      // Safe prime?
        NULL,       // ADD
        NULL,       // REM
        NULL        // CALLBACK
        );

    BN_generate_prime_ex(
        const_cast<BIGNUM*>(manager.get_asset(BN_Q)),
        arg_n, 
        false,      // Safe prime?
        NULL,       // ADD
        NULL,       // REM
        NULL        // CALLBACK
        );


    // Needs to be implemented.





#ifdef __PRINT
    auto clk_end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = clk_end - clk_start;

    std::cerr << "do_keygen_r >\tDone. (elapsed: " << elapsed_seconds.count() << "s)\n";
#endif

    return 0;
}


/*
 * do_keygen_r
 */
int EE488::SchnorrSignature::do_keygen_r(const int arg_bits) {
    
#ifdef __PRINT
    auto clk_start = std::chrono::steady_clock::now();
#endif

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
#ifdef __PRINT
        std::cerr << "ERROR, DSA_generate_key\n";
        std::cout << "ERROR, DSA_generate_key\n";
#endif
        return -1;
    }
    
    /* Setting three parameters, p q g */
    manager.set_asset(const_cast<BIGNUM*>(DSA_get0_p(dsa_key)), BN_P);
    manager.set_asset(const_cast<BIGNUM*>(DSA_get0_q(dsa_key)), BN_Q);
    manager.set_asset(const_cast<BIGNUM*>(DSA_get0_g(dsa_key)), BN_G);

    /* Official API returns it as const BIGNUM. 
     *  Safe to convert, since no modifications are done.
     */

    manager.set_keys(
        const_cast<BIGNUM*>(DSA_get0_pub_key(dsa_key)),
        const_cast<BIGNUM*>(DSA_get0_priv_key(dsa_key))
    );

    /* Record to file when __PRINT is enabled.
     *  Best for debugging purpose.
     */
    {

#ifdef __PRINT
        std::cerr << "do_keygen_r >\tWriting to log...\n";

        FILE* fp = std::fopen("./params.log", "w");

        std::fprintf(fp, "p\t"),    BN_print_fp(fp, manager.get_asset(BN_P));
        std::fprintf(fp, "\nq\t"),  BN_print_fp(fp, manager.get_asset(BN_Q));
        std::fprintf(fp, "\ng\t"),  BN_print_fp(fp, manager.get_asset(BN_G));
        std::fprintf(fp, "\npk\t"),  BN_print_fp(fp, manager.get_asset(BN_PK));
        std::fprintf(fp, "\nsk\t"),  BN_print_fp(fp, manager.get_asset(BN_SK));
        std::fprintf(fp, "\n");

        std::fclose(fp);

        auto clk_end = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed_seconds = clk_end - clk_start;

        std::cerr << "do_keygen_r >\tDone. (elapsed: " << elapsed_seconds.count() << "s)\n";
#endif

    }

    /* OpenSSL's API is only used for generating keys.
     * No more use further. Thus just delete the object.
     */
    DSA_free(dsa_key);  

    key_ready = true; // Now the key is ready to go.

    return 0;
}



/*
 * do_regmsg
 */
int EE488::SchnorrSignature::do_regmsg(const char* arg_pmsg) {
    std::strcpy(reinterpret_cast<char *>(mstr), arg_pmsg);

#ifdef __PRINT
    std::cout << "do_regmsg >\tRegistered string: \n\t\t" << this->mstr << "\n";
#endif

    msg_ready = true;// Now the original message is ready to go.
    return 0;
}


/*
 * do_hash
 */
int EE488::SchnorrSignature::do_hash() {

    return this->do_hash(reinterpret_cast<char *>(this->mstr));
}


int EE488::SchnorrSignature::do_hash(const char* arg_str) {
    
    return this->do_hash(std::string(arg_str));
}


int EE488::SchnorrSignature::do_hash(std::string arg_str) {

    int ret_code = 0;

    if (!is_key_ready()) {
#ifdef __PRINT
    std::cerr << "do_hash >\tError, message not ready.\n";
    std::cout << "do_hash >\tError, message not ready.\n";
#endif
        return -1;
    }

#ifdef __PRINT
    auto clk_start = std::chrono::steady_clock::now();
#endif

    if (!SHA256_Init(&sha_context)) {
#ifdef __PRINT
        std::cout << "do_hash>\tError, SHA256_Init\n";
#endif
        ret_code = -1;
    }

    if(!SHA256_Update(&sha_context, arg_str.c_str(), arg_str.length())) {
#ifdef __PRINT
		std::cout << "do_hash>\tError, SHA256_Update\n";
#endif
        ret_code = -1;
    }

	if(!SHA256_Final(sha_digest, &sha_context)) {
#ifdef __PRINT
		std::cout << "do_hash>\tError, SHA256_Final\n";
#endif
        ret_code = -1;
    }

#ifdef __PRINT
        auto clk_end = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed_seconds = clk_end - clk_start;

        std::cerr << "do_hash >\tDone. (elapsed: " << elapsed_seconds.count() << "s)\n";
#endif

    {
        BIGNUM* hash_val = const_cast<BIGNUM*>(manager.get_asset(BN_E));

        /* Conversion */
        BN_bin2bn(sha_digest, sizeof(sha_digest), hash_val);
        
#ifdef __PRINT 
        FILE* fp = std::fopen("./hash.log", "w");
        std::fprintf(fp, "Given string\t");
        std::fprintf(fp, arg_str.c_str());
        std::fprintf(fp, "\nHashed\t"), BN_print_fp(fp, hash_val);
        std::fclose(fp);
#endif
        // BN_free(hash_val);
    }

    return ret_code;
}



/*
 * do_sign
 */
int EE488::SchnorrSignature::do_sign() {
    
    if (!is_key_ready() || !is_msg_ready()) {
#ifdef __PRINT
    std::cout << "do_sign >\tError, key/msg is not ready.\n";
#endif

        return -1;
    }

#ifdef __PRINT
    auto clk_start = std::chrono::steady_clock::now();
#endif

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

        /* Second round.
         */
        unsigned char arr_r2bin[512] = { 0, };

        BN_bn2bin(manager.get_asset(BN_R), arr_r2bin);

        std::strcat(
            reinterpret_cast<char*>(mstr), 
            reinterpret_cast<char*>(arr_r2bin)
        );

        /* Run hashing */
        if (do_hash()) return -1;

#ifdef __PRINT
        std::cout << "do_sign >\tHashed (E): ";
        BN_print_fp(stdout, manager.get_asset(BN_E)), 
        std::cout << "\n";
#endif
  

        BN_mod_mul(
            const_cast<BIGNUM*>(manager.get_asset(BN_R)),
                                        // Save to, r
            manager.get_asset(BN_SK),   // secret key
            manager.get_asset(BN_E),    // e
            manager.get_asset(BN_Q),    // q
            tbn_ctx
        );

        BN_mod_add(
            const_cast<BIGNUM*>(manager.get_asset(BN_S)),
            manager.get_asset(BN_R),
            tbn,
            manager.get_asset(BN_Q),
            tbn_ctx
        );

#ifdef __PRINT
        std::cout << "\t\tSigned [S]: ";
        BN_print_fp(stdout, manager.get_asset(BN_S)), 
        std::cout << "\n";

        std::cout << "\t\tSigned [E]: ";
        BN_print_fp(stdout, manager.get_asset(BN_E)), 
        std::cout << "\n";
#endif

        BN_free(tbn);

    }
 

#ifdef __PRINT
    auto clk_end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = clk_end - clk_start;

    std::cerr << "do_sign >\tDone. (elapsed: " << elapsed_seconds.count() << "s)\n";
#endif

    sign_ready = true;
    
    return 0;
}



/*
 * do_verify
 */
int EE488::SchnorrSignature::do_verify() {

    int ret_code = 0;

    if (
        !is_key_ready() || 
        !is_msg_ready() ||
        !is_sign_ready()                    // All threes should be ready.
        ) {
#ifdef __PRINT
    std::cout << "do_verify >\tError, key/msg is not ready.\n";
#endif

        return -1;
    }

#ifdef __PRINT
    auto clk_start = std::chrono::steady_clock::now();
#endif

#ifdef __PRINT
    
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
            manager.get_asset(BN_PK),       // public key
            manager.get_asset(BN_E),        // e
            tbn_ctx
        );

        /*
         * tbn_1 * tbn_2 = g^s * {PK^{-1}}^e
         */
        BN_mod_mul(
            const_cast<BIGNUM*>(manager.get_asset(BN_V)),
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

#ifdef __PRINT
        std::cout << "do_verify >\tHashed (V): ";
        BN_print_fp(stdout, manager.get_asset(BN_V)), 
        std::cout << "\n";
#endif

        std::strcat(
            reinterpret_cast<char*>(mstr),  
            reinterpret_cast<char*>(arr_v2bin)
        );

        /* Run hashing */
        if (do_hash()) return -1;

        BN_free(tbn_1), BN_free(tbn_2);
    }

    BN_bin2bn(
        get_sha_digest(),
        sizeof(sha_digest),
        const_cast<BIGNUM*>(manager.get_asset(BN_NE))
        );

#ifdef __PRINT
        std::cout << "do_verify >\tNew [E]: ";
        BN_print_fp(stdout, manager.get_asset(BN_NE)), 
        std::cout << "\n";

        std::cout << "do_verify >\tOld [E]: ";
        BN_print_fp(stdout, manager.get_asset(BN_E)), 
        std::cout << "\n";
#endif

    ret_code = BN_cmp(
        manager.get_asset(BN_E),
        manager.get_asset(BN_NE)
        );

#ifdef __PRINT
    auto clk_end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = clk_end - clk_start;

    std::cerr << "do_sign >\tDone. (elapsed: " << elapsed_seconds.count() << "s)\n";
#endif

    return ret_code;
}


/*
 * do_reset
 */
int EE488::SchnorrSignature::do_reset() {

    manager.reset_asset(); // Clear all containers
    key_ready = msg_ready = sign_ready = veri_ready = false;

    return 0;
}



