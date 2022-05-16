/* Author: SukJoon Oh
 * Environment: 
 *      Manjaro Quonos 21.2, 
 *      g++ (GCC) 11.2.0,
 *      OpenSSL 1.1.1n (comes default in coreutils)
 * Compilation Option: -lssl -lcrypto
 *      Refer to Makefile for more information.
 * Legal Stuff: None
 */

#define __PRINT

#ifdef __PRINT
#include <chrono>
#include <iostream>
#endif

#ifndef __OPENSSL
#define __OPENSSL
#endif

#include <cstring>
#include "./schnorr.h"

/* BigNumberWrapper Actions */
EE488::BigNumberWrapper::BigNumberWrapper() : actor(BN_new()) {}
EE488::BigNumberWrapper::~BigNumberWrapper() {

    if (actor != nullptr)
        BN_free(actor);
}


/* BigNumberManager Actions */
EE488::BigNumberManager::BigNumberManager() {

    asset = std::vector<bnw_t>(NPARAMS);

    for (auto& elem: asset)
        BN_zero(elem.actor); // Registers the asset.
};



EE488::BigNumberManager::BigNumberManager(std::vector<bnw_t>* arg_asset) {

    // Copies asset
    // Yet impl'd
};



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



/*
 * do_keygen
 */
int EE488::SchnorrSignature::do_keygen() {
    
#ifdef __PRINT
    auto clk_start = std::chrono::steady_clock::now();
#endif

    DSA* dsa_key = DSA_new();

    // https://www.openssl.org/docs/man1.1.1/man3/DSA_generate_parameters_ex.html
    DSA_generate_parameters_ex(
        dsa_key,    // DSA, stores the result in here.
        1024,       // BITS, length of primes p and q and a generator g
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
    
    manager.set_asset(const_cast<BIGNUM*>(DSA_get0_p(dsa_key)), BN_P);
    manager.set_asset(const_cast<BIGNUM*>(DSA_get0_q(dsa_key)), BN_Q);
    manager.set_asset(const_cast<BIGNUM*>(DSA_get0_g(dsa_key)), BN_G);

    manager.set_keys(
        const_cast<BIGNUM*>(DSA_get0_pub_key(dsa_key)),
        const_cast<BIGNUM*>(DSA_get0_priv_key(dsa_key))
    );

    // Write to file 
    {

#ifdef __PRINT
        std::cerr << "do_keygen >\tWriting to log...\n";
#endif
        FILE* fp = std::fopen("./params.log", "w");

        std::fprintf(fp, "p\t"),    BN_print_fp(fp, manager.get_asset(BN_P));
        std::fprintf(fp, "\nq\t"),  BN_print_fp(fp, manager.get_asset(BN_Q));
        std::fprintf(fp, "\ng\t"),  BN_print_fp(fp, manager.get_asset(BN_G));
        std::fprintf(fp, "\npk\t"),  BN_print_fp(fp, manager.get_asset(BN_PK));
        std::fprintf(fp, "\nsk\t"),  BN_print_fp(fp, manager.get_asset(BN_SK));
        std::fprintf(fp, "\n");

        std::fclose(fp);

#ifdef __PRINT
        auto clk_end = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed_seconds = clk_end - clk_start;

        std::cerr << "do_keygen >\tDone. (elapsed: " << elapsed_seconds.count() << "s)\n";
#endif

    }

    DSA_free(dsa_key);
    key_ready = true;

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

    msg_ready = true;
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

    // SHA256_CTX sha_context;

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
        // BIGNUM* hash_val = BN_new();
        BIGNUM* hash_val = const_cast<BIGNUM*>(manager.get_asset(BN_E));

        BN_bin2bn(sha_digest, sizeof(sha_digest), hash_val);
        
        FILE* fp = std::fopen("./hash.log", "w");
        std::fprintf(fp, "Given string\t");
        std::fprintf(fp, arg_str.c_str());
        std::fprintf(fp, "\nHashed\t"), BN_print_fp(fp, hash_val);
        std::fclose(fp);

        // BN_free(hash_val);
    }

    return ret_code;
}



/*
 * do_sign
 */
// int EE488::SchnorrSignature::do_sign() {

//     return do_sign(this->mstr);
// }


int EE488::SchnorrSignature::do_sign() {
    
    // unsigned char* umsg = new unsigned char[arg_msg.size() + 512 + 1];
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
        BIGNUM* tbn = BN_new();
        BN_CTX* tbn_ctx = BN_CTX_new();


        BN_rand_range(
            tbn, 
            manager.get_asset(BN_Q));

        manager.set_asset(tbn, BN_K);
        BN_clear(tbn);

        /* 
         * Signing message, 
         * for randomly chosen k(tbn, BN_K), r = g^k mod p where:
         * r: BN_R
         * g: BN_G
         * p: BN_P
         */
        BN_mod_exp(
            tbn, // BN_R
            manager.get_asset(BN_G),
            manager.get_asset(BN_K),
            manager.get_asset(BN_P),
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

// #ifdef __PRINT
//         std::cout << "do_sign >\tConcat: \n\t\t" << mstr << "\n";
// #endif

        /* Run hashing */
        if (do_hash()) return -1;

#ifdef __PRINT
        std::cout << "do_sign >\tHashed (BIGNUM): ";
        BN_print_fp(stdout, manager.get_asset(BN_E)), 
        std::cout << "\n";
#endif
  

        BN_mod_mul(
            const_cast<BIGNUM*>(manager.get_asset(BN_R)),
            manager.get_asset(BN_SK),
            manager.get_asset(BN_E),
            manager.get_asset(BN_Q),
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

    }
 

#ifdef __PRINT
    auto clk_end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = clk_end - clk_start;

    std::cerr << "do_sign >\tDone. (elapsed: " << elapsed_seconds.count() << "s)\n";
#endif

    sign_ready = true;
    
    return 0;
}



int EE488::SchnorrSignature::do_verify() {

// unsigned char* umsg = new unsigned char[arg_msg.size() + 512 + 1];
    if (!is_key_ready() || !is_msg_ready()) {
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











#ifdef __PRINT
    auto clk_end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = clk_end - clk_start;

    std::cerr << "do_sign >\tDone. (elapsed: " << elapsed_seconds.count() << "s)\n";
#endif

    return 0;
}


int EE488::SchnorrSignature::do_reset() {

    manager.reset_asset(); // Clear all containers
    key_ready = msg_ready = sign_ready = false;

    return 0;
}



