// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2008-2018 ANSSI. All Rights Reserved.
/**
 * @file civil-crypto.c
 * Implementation of gen_crypt.h using OpenSSL
 *
 * Copyright (C) 2015 SGDSN/ANSSI
 *
 * @author Marion Daubignard <clipos@ssi.gouv.fr>
 *
 * All rights reserved.
 */

#include "civil-chk_ctx.h"
#include "civil-structures.h"
#include "gen_crypt.h"
#include "x509_get_ext.h"

#include <openssl/x509v3.h>

#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <string.h>
#include <syslog.h>

#define CRL_DISABLED 0
#define CRL_ENABLED 1

// Helper to print out OpenSSL error.
// Only the last error is printed out by default,
// while the whole error stack gets displayed in case g_verbose >1.
static void
print_openssl_error(void)
{
	unsigned long l;
	char buf[256];
	char buf2[4096];
	const char *file, *data;
	int line, flags;

	l = ERR_get_error_line_data(&file, &line, &data, &flags);
	if (l != 0) {
		// translates error code l into a string if there exists one
		// (sometimes not error string is provided)
		ERR_error_string_n(l, buf, sizeof buf);
		snprintf(buf2, sizeof(buf2), "%s:%s:%d:%s\n", buf, file, line,
		         (flags & ERR_TXT_STRING) ? data : "");
		ERROR("%s", buf2);
	}
	/* Keep unpiling errors from the stack if verbose */
	if (g_verbose > 0) {
		l = ERR_get_error_line_data(&file, &line, &data, &flags);
		while (l != 0) {
			// translates error code l into a string if there
			// exists one (sometimes not error string is provided)
			ERR_error_string_n(l, buf, sizeof buf);
			snprintf(buf2, sizeof(buf2), "%s:%s:%d:%s\n", buf, file, line,
			         (flags & ERR_TXT_STRING) ? data : "");

			// Once we have in buf2 a null termintaed string with
			// the error message, we directly  it to syslog.
			// This choice allows to have one OpenSSL per line in
			// the logs when using syslog (doing an strcat with \n
			// between errors of the stack apparently still results
			// in the display on one line of everything).
			ERROR("%s", buf2);
			l = ERR_get_error_line_data(&file, &line, &data, &flags);
		}
	}
	// OpenSSL manpage says not to free file and data, since they are freed
	// by err lib, automatically...
	return;
}

// Function extracting the subject name of a certificate and outputting it in
// form of a null-terminated string of maximal length len.
// This function is the only one using BIOs manually in the whole library,
// A design choice is to not use them to avoid mistakes, which turn out to be
// possible everywhere but for this particular feature.
// Indeed, while X509_NAME_oneline exists and does what we do here, it is
// deprecated and openSSL manual explicitly advises against using it.
// NB : x509_cert cannot be const because of X509_get_subject_name, prototype
// imposed by openSSL.
static gen_crypt_ret
get_X509_subj_name(X509 *x509_cert, char *subj_name, const int len)
{
	// pointer to hold the result of x509_get_subject_name -> must not be freed
	// according to openSSL man (that would corrupt memory of the actual
	// certificate content)
	X509_NAME *certsubject = NULL;
	BIO *bio = NULL;

	if (x509_cert == NULL) {
		DEBUG("Unexpected use of get_X509_subj_name");
		return C_NOK;
	}
	/* X509_get_subject_name dereferences the right member in error_cert ->
	 * OK if error_cert non-null */
	certsubject = X509_get_subject_name(x509_cert);
	if (certsubject == NULL) {
		// TODO : confirm that it is an error, i.e. confirm that "" as
		// a subject name does yield a pointer on "" her, rater than a
		// NULL pointer.
		goto out;
	}
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		goto out;

	/* X509_NAME_print_ex returns the len written, -1 on error */
	// TODO : I think it should set outlen to 1 when reading "" (since
	// there is /one/ character written, '\0'
	// -> To test!! this is REALLY not obvious in the source.
	// There is no guarantee by this function that the output is
	// null-terminated.

	int outlen = X509_NAME_print_ex(bio, certsubject, 0,
	                                XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB &
	                                    ~XN_FLAG_SPC_EQ);
	if (outlen < 0) {
		goto out;
	} else if (outlen == 0) {
		/* While -1 is an error, 0 is not, in the OpenSSL sense. */
		goto noerr;
	}
	// here outlen >=1, we now check whether it is greater than len-1, to
	// truncate
	// the bio if needed
	if (outlen > len - 1) {
		outlen = len - 1;
	}
	/* Now we try to write from 1 to len-1 in subj_name */
	int ret = BIO_read(bio, subj_name, outlen);
	// TODO : tester un peu ça... renvoie-t-il bien 1 quand il lit "",
	// et essayer d'écrire plus, d'un caractère ou de carrément plus, pour
	// vérifier que ça ne marche pas.
	if (ret < 0) { /* OpenSSL error*/
		goto out;
	} else if (ret < outlen) {
		/* We did not succeed in reading everything */
		goto noerr;
	}
	/* Here, we did read everything and write the ultimate null character.
	 * Here we have ret >= outlen >= 1, and outlen <= len-1. */
	subj_name[outlen] = '\0';
	BIO_free(bio);
	return C_OK;
out:
	print_openssl_error();
noerr:
	ERROR("Error in getting subject name of certificate.");
	BIO_free(bio);
	return C_NOK;
}

// TODO : add forced randomness initialization (seems to happen automatically
// in Linux distros). How to do that nicely remains to be determined...
// it seems a best practise, while on Unix any query for random byte seems to
// poll /dev/urandom anyways.
gen_crypt_ret
gen_crypt_init()
{
	DEBUG("Crypto library initialized");
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_load_BIO_strings();
	return C_OK;
}

gen_crypt_ret
gen_crypt_end()
{
	EVP_cleanup();
	ERR_free_strings();
	return C_OK;
}

/* When successful, *sid_ptr is updated with the id of the
 * signature algorithm listed in the certificate my_cert.
 * Function only successful when the signature algorithm is
 * one of the implemented algorithm.
 */
static gen_crypt_ret
get_sig_id(const X509 *my_cert, gen_crypt_sig_id *sid_ptr)
{
	gen_crypt_sig_id local_sid = OBJ_obj2nid(my_cert->sig_alg->algorithm);
	/* In case of error, returns NID_undef*/
	if (local_sid == NID_undef) {
		print_openssl_error();
		return C_NOK;
	}

	// TODO : add RSA
	if (local_sid == NID_ecdsa_with_SHA256 ||
	    local_sid == NID_ecdsa_with_SHA512) {
		*sid_ptr = local_sid;
		return C_OK;
	}
	ERROR("Certified signature algorithm not supported");
	return C_NOK;
}

/* /!\ This has no relation with checks of certification chain
* performed on certificates used in signature verification.
* This function checks whether certificate has a subject name matching
* regexp in re.
* Returns 0 when successful, -1 otherwise.
* NB : X509_ptr should ideally be const, but the prototype of
* get_X509_subj_name cannot allow it because of X509_get_subject_name's
* prototype,
* decided in openSSL.
* */
static inline gen_crypt_ret
check_subject(X509 *X509_ptr, const char *re)
{
	regex_t regex;
	char sn[2048];
	unsigned int ret = C_NOK;

	/* regcomp must have non-null second argument,
	 * so as get_x509_subj_name*/
	if (re == NULL)
		return C_OK;

	if (X509_ptr == NULL) {
		ERROR("Unexpected use of function.");
		return C_NOK;
	}

	if (regcomp(&regex, re, REG_NOSUB | REG_EXTENDED)) {
		ERROR("Failed to compile regex: %s", re);
		return C_NOK;
	}

	if (get_X509_subj_name(X509_ptr, sn, 2048) != C_OK) {
		ERROR("Failed to get public key subject name.");
		goto out;
	}
	DEBUG("Found subject_name : %s", sn);
	/* sn has to be null-terminated to be fed to regexec,
	 * which is ensured by get_X509_subj_name.*/
	if (regexec(&regex, sn, 0, NULL, 0)) {
		ERROR("Subject name %s does not match regexp %s", sn, re);
		goto out;
	}

	ret = C_OK;
/* Fall through */
out:
	regfree(&regex);
	return ret;
}

/* Checks performed on a certificate intended to be used
 * to be concatenated to a signed package.
 * /!\ This has no relation with checks on chains performed
 * on certificates used in signature verification.
 * This function should check that at the time it is called
 * the referenced key is still valid for at least MIN_VALIDITY
 * and issue a warning if it expires in less than WARN_VALIDITY
 */
static gen_crypt_ret
check_time(const X509 *X509_ptr)
{
	time_t cur_date;
	const ASN1_TIME *not_before = NULL;
	const ASN1_TIME *not_after = NULL;
	int pday = 0;
	int psec = 0;
	int sec_diff = 0;

	if (X509_ptr == NULL) {
		DEBUG("Null pointer to certificate");
		return C_NOK;
	}

	/* 1. Check that the certificate is already valid */
	cur_date = time(NULL);
	not_before = X509_get_notBefore(X509_ptr);
	if (not_before == NULL) {
		DEBUG("X509_get_notBefore returned wrong value");
		print_openssl_error();
		return C_NOK;
	}
	if (X509_cmp_time(not_before, &cur_date) > 0) {
		DEBUG("Certificate used is not valid yet");
		return C_NOK;
	}

	/* 2. Check that it is not about to expire */
	not_after = X509_get_notAfter(X509_ptr);
	if (not_after == NULL) {
		DEBUG("X509_get_notAfter returned wrong value");
		print_openssl_error();
		return C_NOK;
	}
	/* This call sets pday and psec to the (signed) difference
	 * between expiration date (not_after) and current time
	 * (because we perform the call using NULL)*/
	if (!ASN1_TIME_diff(&pday, &psec, NULL, not_after)) {
		DEBUG("ASNI_TIME_diff failed");
		print_openssl_error();
		return C_NOK;
	}
	sec_diff = pday * 86400 + psec;
	if (sec_diff < MIN_VALIDITY) {
		/* this condition holds
		 * in particular if sec_diff is negative, meaning that
		 * certificate has expired */
		ERROR("Certificate has expired or is about to");
		return C_NOK;
	}
	if (sec_diff < WARN_VALIDITY) {
		ERROR("WARNING : CERTIFICATE IS EXPIRING SOON");
		/* no error, just the warning*/
	}
	return C_OK;
}

/* Function to get the .pem certificate file in file_name in PEM format
 * and to translate into DER format before copying it into the string_t
 * variable cert. Function also updates sid_ptr with a reference to the signing
 * algo specified in the certificate, and will fail if this algo is not
 * supported.
 */
gen_crypt_ret
gen_crypt_get_certificate(const char *file_name, string_t *cert,
                          gen_crypt_sig_id *sid_ptr, const char *regexp)
{
	FILE *cert_fp;
	unsigned char *DERstring = NULL;
	X509 *X509_cert;

	cert_fp = fopen(file_name, "r");
	if (cert_fp == NULL) {
		int err_rv = errno;
		ERROR("Problem opening certificate %s, fopen failed: %s", file_name,
		      strerror(err_rv));
		return C_NOK;
	}

	/* Now, we load the X509 pem certificate referenced by the file pointer
	 * cert_fp in X509_cert.
	 * If second argument non-null, a call to PEM_read_X509
	 * puts the resulting pointer on an X509
	 * certificate there (same result as the return value)
	 * X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u);
	 * We choose not to use passwords to protect certificates, because
	 * it does not seem useful in our use-case.
	 */

	/* initialization of the place where we put the certificate pointer is
	 * mandatory when using this function call */
	X509_cert = NULL;
	PEM_read_X509(cert_fp, &X509_cert, NULL, NULL);
	if (X509_cert == NULL) {
		ERROR("Error reading certificate");
		print_openssl_error();
		goto err;
	}

	if (get_sig_id(X509_cert, sid_ptr) != C_OK) {
		ERROR("Unsupported algorithm in certificate");
		goto err;
	}

	if (check_time(X509_cert) != C_OK) {
		ERROR("Certificate does not satisfy time validity requirements");
		goto err;
	}
	if (check_subject(X509_cert, regexp) != C_OK) {
		ERROR("Certificate does not correspond to regexp");
		goto err;
	}

	/* Conversion in DER format, which updates an unsigned char * and
	 * outputs the length of the string written as an int.
	 * Our output cert being a string_t we have to convert this to char *
	 * (which is harmless because this is raw data) and uint32_t (after
	 * verifications). */
	int len = i2d_X509(X509_cert, &DERstring);
	if (len < 0) {
		ERROR("Error in DER encoding");
		print_openssl_error();
		goto err;
	}
	/* OK because positive int, of length 32 bits */
	cert->len = (uint32_t)len;
	cert->data = (char *)DERstring;
	fclose(cert_fp);
	return C_OK;
err:
	if (DERstring)
		free(DERstring);
	if (X509_cert)
		X509_free(X509_cert);
	fclose(cert_fp);
	return C_NOK;
}

/* gen_crypt_init_sign updates context with a pointer to the secret key stored
 * in .pem format in the file referenced by priv_info
 */
gen_crypt_ret
gen_crypt_init_sign(gen_crypt_ctx *ctx, const gen_crypt_priv_info *priv_info)
{
	FILE *privkeyfile;
	string_t pwd;
	pwd.data = NULL;
	pwd.len = 0;
	unsigned int ret = C_NOK;
	const string_t *key = NULL;
	const string_t *pwd_file = NULL;

	if (get_key(priv_info, &key) != C_OK) {
		ERROR("Failed to get name of key file");
		return C_NOK;
	}

	privkeyfile = fopen(key->data, "r");
	if (privkeyfile == NULL) {
		int err_rv = errno;
		ERROR("Problem opening key %s, fopen failed: %s", key->data,
		      strerror(err_rv));
		return C_NOK;
	}

	if (get_pwd(priv_info, &pwd_file) != C_OK) {
		ERROR("Eror getting name of password file");
		goto end_fclose;
	}

	if (pwd_file->data != NULL) {
		/* if a path to a file containing a pwd was specified, then
		 * retrieve password value */
		if (get_string_from_file(pwd_file->data, &pwd)) {
			ERROR("Problem retrieving password from %s", pwd_file->data);
			goto end_fclose;
		}
	}

	/* EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x,
	 *                                        pem_password_cb *cb, void *u);
	 * Three behaviors are possible with this function : if last argument
	 * is NULL and key is encrypted, then it prompts for the password, if
	 * last argument is NULL and key is in clear text, key is loaded, if
	 * last argument points to a null-terminated string, it is taken as
	 * password value to decrypt the key if it is encrypted (if key is not
	 * encrypted, it seems to be ignored even if non-NULL).
	 */

	*ctx = PEM_read_PrivateKey(privkeyfile, NULL, NULL, pwd.data);
	if (*ctx == NULL) {
		ERROR("Error while getting private key");
		goto end_string_free;
	}
	ret = C_OK;

/* Fall through */
end_string_free:
	/* If non-null pointer to string, zero-izes and frees memory*/
	string_free(&pwd);

end_fclose:
	fclose(privkeyfile);

	return ret;
}

/* To compute a hash with hash algorithm referenced by sid, do_hash allocates a
 * buffer of the right length, and updates hash and len to contain a pointer to
 * the hash value and its length (in bytes).
 *
 * Note : return values for hash functions SHA256 and SHA512 are not tested :
 * they are wrappers that return a pointer to the hash value.
 * See OpenSSL : crypto/sha/sha256.c for example.
 */
static gen_crypt_ret
do_hash(const gen_crypt_sig_id sid, const unsigned char *to_hash,
        const uint32_t to_hash_len, unsigned char **hash, uint32_t *len)
{
	switch (sid) {
		case NID_ecdsa_with_SHA256:
			*len = 32;
			*hash = malloc(32);
			if (*hash == NULL) {
				ERROR("could not allocate memory");
				return C_NOK;
			}
			/* explicit cast to size_t is OK here
			 * since sizeof(size_t)>=32 bits and
			 * to_hash_len is a uint32_t.
			 */
			SHA256(to_hash, (size_t)to_hash_len, *hash);
			break;
		case NID_ecdsa_with_SHA512:
			*len = 64;
			*hash = malloc(64);
			if (*hash == NULL) {
				ERROR("could not allocate memory");
				return C_NOK;
			}
			/* explicit cast to size_t is OK here
			 * since sizeof(size_t)>=32 bits and
			 * to_hash_len is a uint32_t.
			 */
			SHA512(to_hash, (size_t)to_hash_len, *hash);
			break;
		// TODO : RSA
		default:
			// ERROR("Error with hash algorithm");
			ERROR("unsupported hash algorithm");
			return C_NOK;
	}

	return C_OK;
}

gen_crypt_ret
default_hash(char *to_hash, uint32_t to_hash_len, char **hash, uint32_t *len)
{
	return do_hash(NID_ecdsa_with_SHA256, (const unsigned char *)to_hash,
	               to_hash_len, (unsigned char **)hash, len);
}

/* updates signature with the ECDSA signature of to_sign using hash algo
 * specified in sid
 * and private key priv_key.
 * If successful, signature->data is allocated.
 * Fails when signature is NULL.
 * priv_hdl cannot be const because of the prototype struct ec_key_st
 * *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);
 */
static gen_crypt_ret
sign_ecdsa(const gen_crypt_ctx ctx, const string_t *to_sign,
           const gen_crypt_sig_id sid, string_t *signature)
{
	unsigned char *digest_data;
	uint32_t digest_len = 0;
	gen_crypt_ret ret = C_NOK;
	EC_KEY *privkey = NULL;

	if (signature == NULL || to_sign == NULL || ctx == NULL) {
		ERROR("Invalid use of sign_ecsda");
		return ret;
	}

	/* Explicit cast necessary for functions in OpenSSL that used unsigned
	 * char *. Such a cast is harmless because what is manipulated here is
	 * pure raw data, not signed information.
	 */
	if (do_hash(sid, (const unsigned char *)to_sign->data, to_sign->len,
	            &digest_data, &digest_len) != C_OK) {
		ERROR("Failed in hash computation");
		return ret;
	}

	/* Unwrapping EVP key as an EC key */

	if (ctx == NULL) {
		ERROR("Invalid use of sign_ecsda");
		return ret;
	}
	privkey = EVP_PKEY_get1_EC_KEY(ctx);
	if (privkey == NULL) {
		ERROR("EVP_PKEY_get1_EC_KEY");
		goto err;
	}

	/* to initialize the string_t *signature, we need to know its size: we
	 * use ECDSA_size, which returns 0 on error and positive length on
	 * success */
	int len = ECDSA_size(privkey);
	if (len > 2048) {
		ERROR("This is weird for a result of ECDSA_size!!");
		goto perr;
	}
	if (len == 0) {
		ERROR("ECDSA_size error");
		goto perr;
	}
	/* here conversion is OK since 0<len<2048 */
	signature->len = (uint32_t)len;

	unsigned char *sign_buf = malloc(signature->len);
	if (sign_buf == NULL) {
		ERROR("could not allocate memory");
		goto perr;
	}

	/* perform the signature, returning 1 if successful and 0 on error */
	if (ECDSA_sign(0, digest_data, (int)digest_len, sign_buf, &(signature->len),
	               privkey) != 1) {
		ERROR("ECSDA_sign error");
		free(sign_buf);
		goto perr;
	} else {
		signature->data = (char *)sign_buf;
		ret = C_OK;
	}

perr:
	EC_KEY_free(privkey);
err:
	free(digest_data);
	return ret;
}

/* signature wrapper : signing to_sign with algorithm sid using private
 * key referenced by priv_hdl, updating signature with the result
 * If successful, signature->data is allocated.
 */
gen_crypt_ret
gen_crypt_sign(const gen_crypt_ctx ctx, string_t *to_sign,
               const gen_crypt_sig_id sid, string_t *signature)
{
	switch (sid) {
		case NID_ecdsa_with_SHA256:
			return sign_ecdsa(ctx, to_sign, sid, signature);
		case NID_ecdsa_with_SHA512:
			return sign_ecdsa(ctx, to_sign, sid, signature);
		// TODO : add RSA here
		default:
			ERROR("signature algorithm not supported");
			return C_NOK;
	}
}

gen_crypt_ret
gen_crypt_end_sign(gen_crypt_ctx ctx)
{
	EVP_PKEY_free(ctx); // OpenSSL doc says that NULL argument are
	                    // handled properly
	return C_OK;
}

static gen_crypt_ret
add_dir_lookup(X509_STORE *store, const char *name)
{
	X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
	if (lookup == NULL) {
		ERROR("X509_STORE_add_lookup: could not allocate a new lookup"
		      " for the directory '%s'",
		      name);
		return C_NOK;
	}
	int ret = X509_LOOKUP_add_dir(lookup, name, X509_FILETYPE_PEM);
	if (ret != 1) {
		ERROR("X509_LOOKUP_add_dir: could not add directory '%s' to"
		      " lookup",
		      name);
		return C_NOK;
	}
	DEBUG("added directory '%s' to x509 store lookup", name);
	return C_OK;
}

/* Controls that certificate pubcert is a v3 certificate with a
 * basic constraints extension containing "CA : TRUE" and
 * a key usage extension with either only CertSign usage set (in which case
 * load_crl remains unchanged) or CertSign and CRLsign usages set (and no other)
 * (in which case load_crl is updated to contain CRL_ENABLED).
 * */
static gen_crypt_ret
check_ca_attributes(X509 *pubcert, int *load_crl)
{
	uint32_t exflags = X509_get_extension_flags(pubcert);

	if (exflags & EXFLAG_V1) {
		ERROR("X509v3 certificates required");
		return C_NOK;
	}

	if (!(exflags & EXFLAG_BCONS)) {
		ERROR("Required field basic constraints");
		return C_NOK;
	}

	if (!(exflags & EXFLAG_CA)) {
		ERROR("Required basic constraint : CA : "
		      "TRUE");
		return C_NOK;
	}

	if (!(exflags & EXFLAG_KUSAGE)) {
		ERROR("Required key usage field");
		return C_NOK;
	}

	uint32_t flags = X509_get_key_usage(pubcert);

	if (flags == (KU_KEY_CERT_SIGN | KU_CRL_SIGN)) {
		*load_crl = CRL_ENABLED;
	} else if (flags != KU_KEY_CERT_SIGN) {
		ERROR("Invalid combination of key usages");
		return C_NOK;
	}

	return C_OK;
}

/* Function to be used in directory filtering. returns C_OK if the certificate
 * referenced by file respects all constraints imposed on a CA, C_NOK otherwise.
 * @file          : CA file controlled. Must be a PEM format
 * @load_crl      : flag positionned to CRL_ENABLED whenever the CA parsed
 * posesses the key usage necessary to sign CRL.
 */
static gen_crypt_ret
check_ca_file(const char *file, int *load_crl)
{

	X509 *pubcert = NULL;
	FILE *fp_cert = NULL;
	unsigned int ret = C_NOK;

	fp_cert = fopen(file, "r");

	if (fp_cert == NULL) {
		ERROR_ERRNO("Problem opening certificate file %s", file);
		return ret;
	}

	pubcert = PEM_read_X509(fp_cert, NULL, NULL, NULL);

	fclose(fp_cert);
	if (pubcert == NULL) {
		ERROR("Error loading certificate %s", file);
		print_openssl_error();
		goto err;
	}

	if (check_ca_attributes(pubcert, load_crl) != C_OK) {
		ERROR("Error during control of certificate %s", file);
		goto err;
	}

	ret = C_OK;
	DEBUG("CA file %s passed the conformity test", file);
/* Fall through*/
err:
	X509_free(pubcert);
	return ret;
}

/*Function filter to pass as an argument of scandir in control_ac_dir,
 * to only symbolic links of the form hash_value.number created by c_rehash
 * */
static int
filter(const struct dirent *d)
{
	regex_t regex;
	const char *re = "\\.[0-9]+$";

	if (regcomp(&regex, re, REG_NOSUB | REG_EXTENDED)) {
		ERROR("Failed to compile regex: %s", re);
		return C_NOK;
	}

	if (regexec(&regex, d->d_name, 0, NULL, 0)) {
		DEBUG("Filename %s does not match regexp %s", d->d_name, re);
		return 0;
	}

	DEBUG("Filename %s matches regexp %s", d->d_name, re);
	return 1;
}

/* Function controlling that all files in CA directory satisfy the
 * set of criteria imposed on CAs. Second argument
 * is set to CRL_ENABLED if one of the CAs in the directory is
 * meant to sign CRL, since we take it to mean that CRLs should then be
 * present and checked.
 * Successful (C_OK) if *all* files could be examined and passed the tests.
 *
 * To be ensured by caller (or getter/setters) : login_info is supposed to be
 * non-NULL in this
 * function. Login_info->key contains at most PATH_MAX cahracters including the
 * NULL terminating byte.
 * */
static gen_crypt_ret
control_ca_dir(const gen_crypt_ca_info *ca_info, int *load_crl)
{

	unsigned int ret = C_NOK;
	const string_t *ca_dir = NULL;

	if (get_ca_dir(ca_info, &ca_dir) != C_OK) {
		ERROR("Error getting CA directory");
		return C_NOK;
	}
	if (ca_dir->len == 0) {
		/* ca_dir was the empty string */
		ERROR("A CA directory must be specified");
		return C_NOK;
	}

	/* ca_full_path is 'ca_dir/file_name\0' with:
	 *   - 'ca_dir PATH_MAX long (including '\0')
	 *   - 'file_name' NAME_MAX long (excluding '\0')
	 * Filenames longer than NAME_MAX will be truncated */
	const size_t ca_full_path_len = PATH_MAX + NAME_MAX + 1;

	char *ca_full_path = malloc(ca_full_path_len);
	if (ca_full_path == NULL) {
		ERROR("Failed to allocate memory");
		return C_NOK;
	}

	/* Build an array of symbolic links created by c_rehash.
	 * The array is sorted alphabetically so that multiple certificates with
	 * the same subject name will be sorted w.r.t. their suffixes.
	 * In filter, we use the filed d_name if dirent as a NULL-terminated
	 * string. Which it should be according to POSIX compliance as we
	 * understand man readdir. */
	struct dirent **certificates = NULL;
	int nb_files = scandir(ca_dir->data, &certificates, &filter, &alphasort);

	if (nb_files < 0) {
		ERROR_ERRNO("Error scanning CA directory: %s", ca_dir->data);
		goto end_free_ca_full_path;
	}
	if (certificates == NULL) {
		ERROR("There must be at least one CA certificate in the CA directory: "
		      "%s\n",
		      ca_dir->data);
		goto end_free_ca_full_path;
	}
	if (nb_files == 0) {
		ERROR("There must be at least one CA certificate in the CA directory: "
		      "%s\n",
		      ca_dir->data);
		goto end_free_certificates;
	}

	for (int i = 0; i < nb_files; ++i) {
		int err = snprintf(ca_full_path, ca_full_path_len, "%s/%s",
		                   ca_dir->data, certificates[i]->d_name);
		if (err < 0) {
			// Extremely unlikely/impossible?
			ERROR("snprintf output error");
			goto end_free_all_certificates;
		}
		if ((size_t)ret >= ca_full_path_len) {
			ERROR("Filename was longer than NAME_MAX and has been truncated");
		}
		if (check_ca_file(ca_full_path, load_crl) != C_OK) {
			goto end_free_all_certificates;
		}
	}
	/* We went through all files in the CA directory and they all checked out.*/
	ret = C_OK;

/* Fall through */
end_free_all_certificates:
	for (int i = 0; i < nb_files; ++i) {
		free(certificates[i]);
	}
end_free_certificates:
	free(certificates);

end_free_ca_full_path:
	free(ca_full_path);

	return ret;
}

// Function to display the reason of verification failure.
// Function should return -1 if something went wrong, 0 if it successfully
// displayed everything it was supposed to.
// If IN DEBUG MODE, we try getting details about the particular certificate
// posing the problem.
static int
print_pb_cert(X509_STORE_CTX *verify_ctx)
{
	X509 *error_cert = NULL;
	char buffer[2048];

	if (verify_ctx == NULL) {
		ERROR(
		    "Function print_pb_cert should not be called with a NULL argument");
		return -1;
	}
	/* X509_STORE_CTX_get_error cannot fail on non-null argument */
	int err_code = X509_STORE_CTX_get_error(verify_ctx);
	ERROR("%s", X509_verify_cert_error_string(err_code));

	/*  IN DEBUG MODE, try getting details by
	 *  displaying the offending certificate causing the failure */
	if (g_verbose < 1)
		return 0;

	error_cert = X509_STORE_CTX_get_current_cert(verify_ctx);
	///!\ error_cert can be NULL in case no certificate is relevant to the error
	if (!error_cert) {
		DEBUG("No particular certificate is relevant for this error");
		return 0;
	}
	if (get_X509_subj_name(error_cert, buffer, 2048) != C_OK) {
		DEBUG("There was a problem displaying the certificate involved in the "
		      "verification failure.");
		return -1;
	}

	DEBUG("The problematic certificate's subject name is the following:");
	DEBUG("%s", buffer);
	return 0;
}

static gen_crypt_ret
check_cert_extensions(X509 *my_cert)
{

	uint32_t exflags = X509_get_extension_flags(my_cert);

	if (exflags & EXFLAG_V1) {
		ERROR("Error with certificate, X509v3 certificates required");
		return C_NOK;
	}

	if (!(exflags & EXFLAG_KUSAGE)) {
		ERROR("Error with certificate, must have a key usage field");
		return C_NOK;
	}

	uint32_t flags = X509_get_key_usage(my_cert);

	if (flags != KU_DIGITAL_SIGNATURE) {
		ERROR("Certificate should only be able to sign data");
		return C_NOK;
	}
	return C_OK;
}

// Function to verify a certificate referenced by my_cert given a verification
// context
// The function should not modify my_cert or what it points to, but
// X509_STORE_CTX_init takes it as argument of type X509 *, so no const is
// possible here.
static gen_crypt_ret
verify_cert_chain(gen_crypt_chk_ctx chk_ctx, X509 *my_cert)
{
	X509_STORE_CTX *vrfy_ctx = NULL;
	X509_STORE *store = NULL;
	unsigned int ret = C_NOK;
	int rv = 0;
	X509 *trusted_ca = NULL;

	// Create the context structure for the validation operation
	vrfy_ctx = X509_STORE_CTX_new();

	if (vrfy_ctx == NULL) {
		ERROR("Error creating certificate verification context");
		print_openssl_error();
		return C_NOK;
	}

	store = get_store(chk_ctx);
	if (store == NULL) {
		ERROR("Error dereferencing certificate store.");
		goto out;
	}
	// Initialize the ctx structure for a verification operation:
	// Set the trusted cert store, the unvalidated cert, and any
	// potential certs that could be needed (here we set it NULL)
	rv = X509_STORE_CTX_init(vrfy_ctx, store, my_cert, NULL);

	if (rv != 1) {
		ERROR("Error initializing certificate verification context");
		print_openssl_error();
		goto out;
	}

	// Check the complete cert chain can be built and validated.
	// Returns 1 on success, 0 on verification failures, and -1
	// when problem with the ctx object (i.e. missing certificate)
	rv = X509_verify_cert(vrfy_ctx);

	if (rv == 1) {
		LOG("Verification result text: %s",
		    X509_verify_cert_error_string(vrfy_ctx->error));
		ret = C_OK;
	} else if (rv == 0) {
		print_openssl_error();
		print_pb_cert(vrfy_ctx);
		goto out;
	} else {
		DEBUG("Error in function X509_verify_cert, in the function, and \
			not certificate invalid !");
		print_openssl_error();
		goto out;
	}

	/* And we also want to check that it was issued by chk_ctx's trusted_ca
	 * if it is not NULL.*/
	trusted_ca = get_trusted_x509(chk_ctx);
	if (trusted_ca != NULL) {
		if (X509_check_issued(trusted_ca, my_cert) != X509_V_OK) {
			ERROR("Certificate was not issued by the CA we trust.");
			goto out;
		}
		LOG("Certificate issuer checks out");
	}

/* fall through */
out:
	X509_STORE_CTX_free(vrfy_ctx);
	return ret;
}

/*
 * Initializes a new checking context chk_ctx, making it refer to the
 * initialized global certificate validation store, ready to verify with the
 * certificate and CRL listed in the .pem files listed in the ca_info
 * structure. The certificate cache associated to chk_ctx is invalidated (i.e.
 * it's set up to be empty).
 */
gen_crypt_ret
gen_crypt_init_check(gen_crypt_chk_ctx *chk_ctx,
                     const gen_crypt_ca_info *ca_info)
{
	X509_STORE *store;
	int ret;
	int load_crl = CRL_DISABLED;
	X509 *ca_to_trust = NULL;
	FILE *fp_cert;
	const string_t *ca_dir = NULL;
	const string_t *crl_dir = NULL;
	const string_t *trusted_ca = NULL;

	// check that we still have place to store our new chk session :
	ret = get_new_chk_ctx(chk_ctx);
	if (ret < 0) {
		ERROR("Error initializing new check context : no space left.");
		return C_NOK;
	}

	// creation of a new store
	store = X509_STORE_new();
	if (store == NULL) {
		ERROR("Error creating X509_STORE object");
		print_openssl_error();
		return C_NOK;
	}

	ret = control_ca_dir(ca_info, &load_crl);
	if (ret != C_OK) {
		ERROR("Error in validation of CA repository");
		goto err;
	}

	// loading of certificate directory
	if (get_ca_dir(ca_info, &ca_dir) != C_OK) {
		ERROR("Error in getting CA directory");
		goto err;
	}
	ret = add_dir_lookup(store, ca_dir->data);
	if (ret != C_OK) {
		goto err;
	}

	if (load_crl == CRL_ENABLED) {
		if (get_crl(ca_info, &crl_dir) != C_OK) {
			ERROR("Error in getting CRL directory");
			goto err;
		}

		// loading of CRL directory
		store->cache = 0; // done in stunnel. Document.
		ret = add_dir_lookup(store, crl_dir->data);
		if (ret != C_OK) {
			goto err;
		}
		// Activation of CRL verification
		// First flag = to perform non-revocation checks of leaf certificates,
		// second flag = check for non-revocation of the whole chain of
		// certificates
		ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
		                                      X509_V_FLAG_CRL_CHECK_ALL);
		if (ret != 1) {
			ERROR("Error activating CRL checks");
			print_openssl_error();
			goto err;
		}
	}

	/* Check that we have a trusted certificate and its validity (and that of
	 * associated CRL as a result) */
	if (get_trusted_ca(ca_info, &trusted_ca) != C_OK) {
		ERROR("Error getting trusted CA");
		goto err;
	}

	fp_cert = fopen(trusted_ca->data, "r");

	if (fp_cert == NULL) {
		ERROR_ERRNO("Problem opening certificate file %s", trusted_ca->data);
		goto err;
	}

	ca_to_trust = PEM_read_X509(fp_cert, NULL, NULL, NULL);

	fclose(fp_cert);
	if (ca_to_trust == NULL) {
		ERROR("Error loading certificate %s", trusted_ca->data);
		print_openssl_error();
		goto err;
	}

	if (init_chk_session(*chk_ctx, store, NULL) < 0) {
		ERROR("Error initializing check session");
		return C_NOK;
	}

	if (verify_cert_chain(*chk_ctx, ca_to_trust) != C_OK) {
		ERROR("The CA certificate to trust could not be verified.");
		free_chk_ctx(*chk_ctx);
		return C_NOK;
	}
	LOG("Trusted CA was successfully verified.");

	if (init_chk_session(*chk_ctx, store, ca_to_trust) < 0) {
		ERROR("Error initializing check session");
		free_chk_ctx(*chk_ctx);
		return C_NOK;
	}

	return C_OK;

err:
	X509_STORE_free(store);
	// nb : lookup structure freed by X509_STORE_free when existing
	return C_NOK;
}

// Function to get a pointer on an X509 certificate stored in DER form
// in the string_t variable cert. Certificate is verified w.r.t. context
// chk_ctx
static gen_crypt_ret
parse_and_verify(const gen_crypt_chk_ctx chk_ctx, const string_t *cert,
                 X509 **X509_cert)
{
	// first thing to do is to convert the certificate cert in X509

	const unsigned char *data = (const unsigned char *)(cert->data);

	// get length of certificate (necessary cast
	// from uint32_t to int because of the OpenSSL API)

	int len = (int)cert->len;
	if (len < 0) {
		ERROR("Certificate is too long to be handled");
		return C_NOK;
	}

	// parse certificate from DER to x509
	// first argument = NULL (no certificate reuse, and no copy
	// of the result)
	// after a successful call the pointer data is at the end of the cert
	//-> invalid, do not reuse!

	*X509_cert = d2i_X509(NULL, &data, len);
	if (*X509_cert == NULL) {
		ERROR("Certificate parsing failed");
		print_openssl_error();
		return C_NOK;
	}

	if (verify_cert_chain(chk_ctx, *X509_cert)) {
		ERROR("Problem with the certificate verification in verify_cert_chain");
		return C_NOK;
	}

	return C_OK;
}

// verify_ecdsa_sig verifies that signature is a cryptographically valid
// signature of msg_signed using public key evpkey and (ECDSA based) algorithm
// referenced by sid.
static gen_crypt_ret
verify_ecdsa_sig(string_t *msg_signed, string_t *signature,
                 gen_crypt_sig_id sid, EVP_PKEY *evpkey)
{
	unsigned char *digest_data = NULL;
	uint32_t digest_len = 0;

	// To pass msg_signed->data as argument of hash functions,
	// explicit cast in (unsigned char *). This is  harmless because we
	// exploit raw data here so that sign information is meaningless.

	gen_crypt_ret ret = do_hash(sid, (unsigned char *)msg_signed->data,
	                            msg_signed->len, &digest_data, &digest_len);

	if (ret != C_OK) {
		ERROR("verify_ecdsa_sig: failure during hash");
		return C_NOK; // in case of failure, do_hash is assumed to free
		              // digest_data
	}

	EC_KEY *pkey = EVP_PKEY_get1_EC_KEY(evpkey);
	if (pkey == NULL) {
		ERROR("unable to get verification key");
		goto err;
	}

	// To do so, need to explicitly cast the data field of the string_t
	// structure into (const unsigned char *) which should make
	// no difference since the sign info is not used,
	// and the len field has to be transformed into int.
	// We also have to cast digest_len into an int because OpenSSL
	// chooses to encode digests lengths on signed integers,
	// which is not a problem either since it is not that long anyways.
	int len = (int)signature->len;

	if (len < 0) {
		ERROR("signature is too long to be handled");
		goto err;
	}

	int dlen = (int)digest_len;
	if (dlen < 0) {
		ERROR("Hash value is too long to be handled");
		goto err;
	}

	int rv = ECDSA_verify(0, digest_data, dlen,
	                      (const unsigned char *)signature->data, len, pkey);

	if (rv != 1) {
		ERROR("verification of signature failed");
		goto err;
	}
	LOG("signature verified successfully");

	free(digest_data);
	EC_KEY_free(pkey);
	return C_OK;

err:
	free(digest_data);
	EC_KEY_free(pkey);
	return C_NOK;
}

// gen_crypt_verify verifies the certificate in cert is valid according to the
// info in check_ctx (trusted certification chain and CRLs), with time set to
// current time, and checks that certificate Subject Name
// matches regexp.
//
// If all that checks out, the public key in the certificate cert is used to
// verify the fact that signature is indeed a crytographically valid signature
// of msg_signed using the algorithm specified in the certificate.
//
// Warning: the checkdate arguement is unused for now. Date validity and
// expîration is always performed.
// TODO: Implement date validity verification bypass.
gen_crypt_ret
gen_crypt_verify(const gen_crypt_chk_ctx check_ctx, string_t *msg_signed,
                 const string_t *cert, string_t *signature, const char *regexp,
                 __attribute__((unused)) bool checkdate)
{
	X509 *X509_ptr = NULL;
	gen_crypt_sig_id sid;
	EVP_PKEY *evpkey;
	gen_crypt_ret ret = C_NOK;

	// validation of time of use, non-revocation and certification chain of the
	// certificate
	// that is extracted from its string_t format and parsed as an X509
	// structure.
	if (parse_and_verify(check_ctx, cert, &X509_ptr) != C_OK) {
		return C_NOK;
	}

	// validation of all other criteria (for the time being : regexp on Subject
	// Name) before getting the algorithm

	/* We also want to check that the certificate is a v3 and that it is meant
	  * to sign data AND ONLY THAT !*/
	if (check_cert_extensions(X509_ptr) != C_OK) {
		ERROR("Certificate extensions do not check out.");
		return C_NOK;
	}

	if (check_subject(X509_ptr, regexp) != C_OK) {
		ERROR("gen_crypt_verify failed");
		return C_NOK;
	}
	// validation of algorithm used, sid updated if successful
	if (get_sig_id(X509_ptr, &sid) != C_OK) {
		ERROR("gen_crypt_verify failed");
		return C_NOK;
	}

	// everything is OK with the certificate, let's do the cryptographic part
	// of the verification
	// get the public key value
	evpkey = X509_get_pubkey(X509_ptr);
	if (evpkey == NULL) {
		ERROR("Error in X509_get_pubkey, gen_crypt_verify failed");
		print_openssl_error();
		return C_NOK;
	}

	switch (sid) {
		case NID_ecdsa_with_SHA256:
			ret = verify_ecdsa_sig(msg_signed, signature, sid, evpkey);
			break;
		case NID_ecdsa_with_SHA512:
			ret = verify_ecdsa_sig(msg_signed, signature, sid, evpkey);
			break;
		// TODO case RSA return verify_rsa_sig();
		default:
			ERROR("Signature algorithm not dealt with but \
			passed verification criteria : something weird \
			is happening!");
			ret = C_NOK;
	}

	EVP_PKEY_free(evpkey);
	return ret;
}

// This function verifies the validity of signature as a cryptographic
// signature of msg_signed with certificate (verified too) using trusted
// certificates and CRL in check_ctx.
//
// The certificate cert must have a subject name matching regexp if this latter
// is non-null.
//
// Warning: the checkdate arguement is unused for now. Date validity and
// expîration is always performed.
// TODO: Implement date validity verification bypass.
//
// If the cache is valid, and found to match the argument cert, verifications
// performed on the certificate are bypassed and the cached information are
// used to perform the verification of the signature.
gen_crypt_ret
gen_crypt_verify_with_cache(const gen_crypt_chk_ctx check_ctx,
                            string_t *msg_signed, const string_t *cert,
                            string_t *signature, const char *regexp,
                            __attribute__((unused)) bool checkdate)
{

	cached_cert_info cache;

	// 1 - check whether the cache should be updated
	/* Decide if it is needed to update the certificate cache :
	 * it is if the certificate found in the signature block
	 * is not the same as the one previously used
	 * nb : on the first call, this will result in the need to
	 * initialize the cachewith a valid certificate */
	if (default_hash(cert->data, cert->len, &(cache.hash.data),
	                 &(cache.hash.len))) {
		ERROR("Failed to hash new cert");
		return -1;
	}

	int rv = is_cached_cert(check_ctx, &(cache.hash));
	if (rv < 0) {
		ERROR("Problem in cache handling");
		return C_NOK;
	}

	// 2-
	// if update asked (or if cache has been invalidated), try to validate
	// certificate
	if (!rv) {
		// validity of info cached is updated once all cached info is checked
		LOG("Tries to update the cache");
		X509 *X509_ptr = NULL;
		// validation of time of use, non-revocation and certification chain of
		// the certificate
		if (parse_and_verify(check_ctx, cert, &X509_ptr) == C_NOK) {
			return C_NOK;
		}
		// validation of all other criteria (for the time being : regexp on
		// Subject Name) before getting the algorithm
		if (check_subject(X509_ptr, regexp) == C_NOK) {
			ERROR("gen_crypt_verify failed");
			return C_NOK;
		}
		// validation of algorithm used, cache.sid updated if successful
		if (get_sig_id(X509_ptr, &cache.sid) == C_NOK) {
			ERROR("gen_crypt_verify failed");
			return C_NOK;
		}
		// everything is OK, let's finish the update of the cache
		// get the public key value
		cache.evpkey = X509_get_pubkey(X509_ptr);
		if (cache.evpkey == NULL) {
			ERROR("Error in X509_get_pubkey, gen_crypt_verify failed");
			print_openssl_error();
			return C_NOK;
		}
		if (set_cached_cert_info(check_ctx, &cache) < 0) {
			ERROR("Error in cache update");
			return C_NOK;
		}
	} else {
		LOG("Uses the cache without update");
		if (get_cached_cert_info(check_ctx, &cache) < 0) {
			ERROR("Error in cache update");
			return C_NOK;
		}
	}
	// here variable cache contains valid information to use to perform the
	// cryptographic part
	// of the verification

	switch (cache.sid) {
		case NID_ecdsa_with_SHA256:
			return verify_ecdsa_sig(msg_signed, signature, cache.sid,
			                        cache.evpkey);
		case NID_ecdsa_with_SHA512:
			return verify_ecdsa_sig(msg_signed, signature, cache.sid,
			                        cache.evpkey);
		// TODO case RSA return verify_rsa_sig();
		default:
			ERROR("Signature algorithm not dealt with but \
			passed verification criteria : something weird \
			is happening !\n");
			return C_NOK;
	}
}

gen_crypt_ret
gen_crypt_end_check(gen_crypt_chk_ctx check_ctx)
{
	free_chk_ctx(check_ctx);
	return C_OK;
}
