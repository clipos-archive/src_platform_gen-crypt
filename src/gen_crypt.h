// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file gen_crypt.h
 *
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * @copyright All rights reserved.
 *
 * This file defines the cryptographic API used by the software components to
 * sign and verify signature for package updates. This API is meant to be
 * implemented using any underlying implementation of the cryptography, e.g. a
 * library relying on OpenSSL (libcrypto), or using a PKCS#11-compliant token.
 * For the time being, no PKCS#11-compliant library has actually been
 * developed, and PKCS#11-related comments are only what the API design allows
 * to anticipate.
 *
 * @note Operations dealing with certificate checking are not part of the
 * PKCS#11 standard: one has to use another library to carry out these
 * operations.
 *
 * Functions with the return type @e gen_crypt_ret will return @c C_OK on
 * success and @c C_NOK on failure.
 *
 * @section section_opaque Opaque data types in this API
 *
 * @subsection subsection_context Cryptographic contexts
 *
 * There is classically a difference between cryptographic operations dealing
 * with public elements (e.g. certificates and public keys) and those involving
 * secret keys. Certificate operations are not specified in the PKCS#11
 * standard: one has to use another library to carry out these operations.
 * Even in OpenSSL, context information dealt with are of different types
 * compared to non-PKI related operations. We therefore choose to define two
 * different context types (opaque data types):
 *   @li @c gen_crypt_ctx for operations involving private keys,
 *   @li @c gen_crypt_chk_ctx for verification related operations.
 *
 * Specific initialization and finalization routines are implemented for each
 * specific context type, and they do not replace global initialization and
 * finalization functions.
 *
 * Each version (civil) of the library has its own implementation of the
 * checking context. It should be noted that contexts should not be manipulated
 * directly by functions of the gen-crypt library, but only through getters and
 * setters defined on purpose in civil-chk_ctx.h. These files also hold the
 * definition of constant @c MAX_CHK_CTX, which sets at compile time the
 * maximum number of contexts that can be used simultaneously in an instance of
 * the library. Moreover, these files export an interface to cache a user
 * certificate (see gen_crypt_verify_with_cache()).
 *
 * The following functions do not depend on any context:
 *   @li gen_crypt_init() / gen_crypt_end(),
 *   @li gen_crypt_get_certificate(),
 *   @li default_hash(),
 *   @li gen_crypt_init_ca_info() / gen_crypt_free_ca_info(),
 *   @li gen_crypt_init_priv_info() / gen_crypt_free_priv_info().
 *
 * The following functions depend on a gen_crypt_ctx context:
 *   @li gen_crypt_init_sign(),
 *   @li gen_crypt_sign(),
 *   @li gen_crypt_end_sign().
 *
 * The following functions depend on a gen_crypt_chk_ctx context:
 *   @li gen_crypt_init_check(),
 *   @li gen_crypt_end_check(),
 *   @li gen_crypt_verify(),
 *   @li gen_crypt_verify_with_cache().
 *
 * @subsection subsection_priv Information Opaque type related functions
 *
 * Two opaque data types are defined:
 *   @li @c gen_crypt_ca_info: information required for signature verification,
 *   @li @c gen_crypt_priv_info: information required for signature creation.
 *
 * Each underlying library used to implement the gen-crypt API may require
 * different informations for signature creation and validation. As the
 * gen-crypt API must remain generic, the implementation of these types and
 * related functions is private to each underlying library. Programs using the
 * gen-crypt API should not depend on internal properties of those types.
 *
 * The functions available to manipulate those types are:
 *   @li gen_crypt_init_ca_info() / gen_crypt_free_ca_info(),
 *   @li gen_crypt_init_priv_info() / gen_crypt_free_priv_info().
 *
 */

#include "common-protos.h"

// Make sure one cryptographic backend has been chosen
#ifdef CIVIL_GEN_CRYPT
#include "civil-protos.h"
#else
#error "No underlying cryptography chosen!"
#endif /* CIVIL_GEN_CRYPT */

/**
 * @brief Initialize the cryptographic library.
 *
 * Initialization of cryptographic library for general purpose: randomness,
 * loading of error symbols, etc. No context is taken as argument. This call
 * must be performed before any use of other functions of this library and it
 * does not replace in any way initialization for signing (gen_crypt_init_sign)
 * or checking signature (gen_crypt_init_check) that depend on contexts.
 *
 *   @li in OpenSSL: No context used, but if needed initialization of
 *   randomness should be done here.
 *   @li in PKCS#11: C_Initialize would be done here.
 */
gen_crypt_ret gen_crypt_init(void);

/**
 * @brief Finalization function, to undo what gen_crypt_init did.
 */
gen_crypt_ret gen_crypt_end(void);

/**
 * @brief Load and parse a certificate from a file.
 *
 * This function loads a certificate from @c filename and copies to @c cert the
 * string to append to a package signed with the corresponding private key.
 *
 * If @c regexp in a non NULL pointer to a valid regular expression then the
 * certificate subject name must match against it.
 *
 * @note Certificate chain checks are not performed in this function.
 *
 *   @li in OpenSSL: The format used to transmit certificates is DER. However,
 *                   certificates and private keys are provided in PEM format
 *                   by the user of the API. This choice was partially made to
 *                   avoid using OpenSSL BIO related functions.
 *
 * @param[in]  file_name  File containing the certificate to load (PEM in
 *                        OpenSSL).
 * @param[out] cert       string_t containing the certificate if successful.
 * @param[out] sid_ptr    [OpenSSL only] This holds an ID for the signature
 *                        algorithm associated with the key in the certificate.
 * @param[in]  regexp     If non-null, the subject name in the certificate
 *                        parsed has to match this regular expression for the
 *                        function to be successful.
 */
gen_crypt_ret
gen_crypt_get_certificate(const char *file_name, string_t *cert,
                          gen_crypt_sig_id *sid_ptr, const char *regexp);

/**
 * @brief Provide a default good hash function to compare data.
 *
 * The caller does not need to specify the hash algorithm.
 *
 *   @li in OpenSSL: SHA256
 *
 * @param[in]  to_hash     String to hash
 * @param[in]  to_hash_len Length of the string to be hashed
 * @param[out] hash        Resulting hashed string, allocated in the function.
 *                         Caller is responsible for freeing this memory.
 * @param[out] len         Length of hashed string
 * */
gen_crypt_ret
default_hash(char *to_hash, uint32_t to_hash_len, char **hash, uint32_t *len);

/**
 * @brief Opaque data type to store signature validation related informations.
 */
typedef struct gen_crypt_ca_info gen_crypt_ca_info;

/**
 * @brief Opaque data type to store signature creation related informations.
 */
typedef struct gen_crypt_priv_info gen_crypt_priv_info;

/**
 * @brief Allocate and initialize a gen_crypt_ca_info structure.
 *
 * Copy provided paths into a gen_crypt_ca_info structure, while checking the
 * following properties:
 *   @li Ignores NULL arguments.
 *   @li The path is effectively required by the cryptographic library. If not,
 *       non-relevant arguments are ignored and a warning is issued.
 *   @li Strings longer than the expected values (PATH_MAX/NAME_MAX) are
 *       automatically truncated.
 *
 * @param[in]  ca_dir      Path of the CA certificate(s) (in OpenSSL, this is
 *                         a directory).
 *                         Maximum length is PATH_MAX.
 * @param[in]  crl         Path of the CRL (only relevant in OpenSSL).
 *                         Maximum length is PATH_MAX.
 * @param[in]  trusted_ca  Path of the (only) CA certificate trusted to be the
 *                         issuer of the accepted certificates (only relevant
 *                         in OpenSSL).
 *                         Maximum length is NAME_MAX.
 * @param[in]  pwd         Path of the file storing the password used to
 *                         protect the CA certificate in ca_dir.
 *                         Maximum length is PATH_MAX.
 * @param[out] ca_info     Pointer to the resulting updated gen_crypt_ca_info.
 */
gen_crypt_ret gen_crypt_init_ca_info(const char *ca_dir, const char *crl,
                                     const char *trusted_ca, const char *pwd,
                                     gen_crypt_ca_info **ca_info);

/**
 * @brief Free a gen_crypt_ca_info structure.
 *
 * Frees all strings referred to by the structure before freeing the structure
 * itself. Harmless if called on NULL.
 */
void gen_crypt_free_ca_info(gen_crypt_ca_info *ca_info);

/**
 * @brief Allocate and initialize a gen_crypt_priv_info structure.
 *
 * Copy provided paths into a gen_crypt_priv_info structure. Paths longer than
 * PATH_MAX will be truncated.
 *
 * @param[in]   key       Path to the file storing the private key to be used.
 *                        Maximum length is PATH_MAX.
 * @param[in]   pwd       Path to the file storing the password protecting the
 *                        key.
 *                        Maximum length is PATH_MAX.
 * @param[out]  priv_info Pointer to the resulting updated gen_crypt_priv_info.
 */
gen_crypt_ret gen_crypt_init_priv_info(const char *key, const char *pwd,
                                       gen_crypt_priv_info **priv_info);

/**
 * @brief Free a @c gen_crypt_priv_info structure.
 *
 * Frees all strings referred to by the structure before freeing the structure
 * itself. Harmless if called on NULL.
 */
void gen_crypt_free_priv_info(gen_crypt_priv_info *priv_info);

/**
 * @brief Load the private key to use for signature.
 *
 *   @li in OpenSSL: Gets a pointer to the private key into the context.
 *   @li in PKCS#11: opening a session, logging in, getting a handle on the
 *                   private key and storing all this in the context.
 *
 * @param[out]    ctx       Context referencing private cryptographic material
 *                          to be used afterwards
 * @param[in]     priv_info Structure containing paths to the cryptographic
 *                          material to load (namely, private key, and a
 *                          password if it was specified).
 */
gen_crypt_ret
gen_crypt_init_sign(gen_crypt_ctx *ctx, const gen_crypt_priv_info *priv_info);

/**
 * @brief Sign data with the key stored in context.
 *
 * Data in to_sign gets signed by this function, using the signature algorithm
 * stored in sid and private key referenced by the context.
 *
 * This functions should fail if to_sign or signature are NULL or context was
 * not initialized properly.
 *
 * @param[in] ctx       Context referencing the private key to use
 * @param[in] to_sign   Data to be signed
 * @param[in] sid       Only used in OpenSSL, ID of signature algorithm to use
 *                      to sign, which should match the algorithm for which the
 *                      key was generated. Behavior is undefined otherwise.
 *                      This ID can be retrieved when calling get_certificate
 *                      on a certificate matching the private key.
 * @param[out] signature String_t holding the resulting signature and its
 *                       length. Field data is allocated by this function.
 *                       Length is updated with suitable information.
 */
gen_crypt_ret gen_crypt_sign(const gen_crypt_ctx ctx, string_t *to_sign,
                             gen_crypt_sig_id sid, string_t *signature);

/**
 * @brief Close and free resources once signature operations are done.
 *
 * Harmless if @c ctx is NULL.
 *
 *   @li in PKCS#11: C_Logout, C_CloseSession should take place in there.
 */
gen_crypt_ret gen_crypt_end_sign(gen_crypt_ctx ctx);

/**
 * @brief Initialize signature checking context.
 *
 * Initialize the context to check signatures with cryptographic material
 * referenced by ca_info as trusted material.
 *
 * If the maximum number of simultaneous contexts is not reached, a new
 * checking context is initialized based on the content of the ca_info
 * structure.
 *
 *   @li in OpenSSL: This call performs checks on all CA certificates referred
 *                   to by a symlink in a c_rehash format that can be found in
 *                   the CA directory listed in structure ca_info. Details of
 *                   these checks can be found in function control_ca_dir in
 *                   civil-crypto.c.
 *                   If checks pass, then the CA directory and possible CRL
 *                   directory referenced by structure ca_info are loaded in a
 *                   X509 certification store (stored in the checking context).
 *                   The trusted CA certificate specified in ca_info is also
 *                   cryptographically verified here. While it is also verified
 *                   when certificates are validated for each signature
 *                   verification, it allows to stop as of initialization if
 *                   this certificate is not valid.
 *                   NB: the 'real' X509 context initialization in the OpenSSL
 *                   sense must be done with each specific unvalidated
 *                   certificate, and is not factored in this call.
 *
 * @param[out] chk_ctx  If successful, handle to the initialized checking
 *                      context.
 * @param[in]  ca_info  Structure ca_info holding paths to cryptographic
 *                      material to use for verification.
 */
gen_crypt_ret gen_crypt_init_check(gen_crypt_chk_ctx *chk_ctx,
                                   const gen_crypt_ca_info *ca_info);

/**
 * @brief Free checking context.
 */
gen_crypt_ret gen_crypt_end_check(gen_crypt_chk_ctx chk_ctx);

/**
 * @brief Verify a message signature (ignoring potentially cached
 * certificates).
 *
 * Verify the signature provided in signature for message referenced by
 * msg_signed, using certificate cert, which is verified using cryptographic
 * material stored in the checking context.
 *
 * If @c regexp is non NULL, then the certificate must have a subject name
 * matching against it.
 *
 * This function is supposedly completely oblivious of any cached certificate.
 *
 *   @li in OpenSSL: if the signature algorithm is not ECDSA-SHA256 or
 *                   ECDSA-SHA512, verification will fail.
 *                   Validation of cert also checks that issuer of cert matches
 *                   the trusted CA certificate which is loaded in chk_ctx.
 *
 * @param[in] chk_ctx       Checking context which has to be initialized
 * @param[in] msg_signed    Message whose signature is to be verified
 * @param[in] cert          Unvalidated certificate which should hold a public
 *                          key to use to verify the signature
 * @param[in] signature     Signature of above message
 * @param[in] regexp        Regular expression that the certificate subject
 *                          name in argument cert should match
 * @param[in] checkdate     If true, check certificate validity period.
 *                          If false, ignore certificate validity period.
 *
 * @warning Ignoring certificate validity period with the checkdate argument is
 * not implemented as the required functionality is not yet available in the
 * current version of OpenSSL.
 */
gen_crypt_ret
gen_crypt_verify(const gen_crypt_chk_ctx chk_ctx, string_t *msg_signed,
                 const string_t *cert, string_t *signature, const char *regexp,
                 bool checkdate);

/**
 * @brief Verify a message signature and try to use a cached certificate.
 *
 * A one-certificate sized cache is implemented through the interface exported
 * by civil-chk_ctx.h. This function should exclusively use this interface and
 * it should be the only way to access the cache. This does not take into
 * account caching potentially performed by an underlying cryptographic
 * library, which we are not responsible for. Our certificate cache can only
 * hold one certificate at a time for the time being - which is deemed
 * sufficient for the current use of our library.
 *
 * This function tries to determine whether the certificate is the same as that
 * in the cache (by comparing hash values). If it is, certificate verification
 * is completely bypassed and the cached certificate is used.  If it is not,
 * then the certificate cert is verified and if successfully verified, becomes
 * the new cached certificate.
 *
 * After this, verification is performed as in gen_crypt_verify().
 *
 * The signature provided in @c signature for the message referenced by
 * msg_signed, using certificate @c cert, is verified using cryptographic
 * material stored in the checking context @c check_cxt.
 *
 * If @c regexp is non NULL, the certificate must have a subject name matching
 * against it.
 *
 *   @li in OpenSSL: if the signature algorithm is not ECDSA-SHA256 or
 *                   ECDSA-SHA512, verification will fail.
 *                   Validation of cert also checks that issuer of cert matches
 *                   the trusted CA certificate which is loaded in chk_ctx.
 *
 * @param[in] check_ctx     Checking context which has to be initialized
 * @param[in] msg_signed    Message whose signature is to be verified
 * @param[in] cert          Unvalidated certificate which should hold a public
 *                          key to use to verify the signature
 * @param[in] signature     Signature of above message
 * @param[in] regexp        Regular expression that the certificate subject
 *                          name in argument cert should match
 * @param[in] checkdate     If true, check certificate validity period.
 *                          If false, ignore certificate validity period.
 *
 * @warning Ignoring certificate validity period with the checkdate argument is
 * not implemented as the required functionality is not yet available in the
 * current version of OpenSSL.
 */
gen_crypt_ret
gen_crypt_verify_with_cache(const gen_crypt_chk_ctx check_ctx,
                            string_t *msg_signed, const string_t *cert,
                            string_t *signature, const char *regexp,
                            bool checkdate);
