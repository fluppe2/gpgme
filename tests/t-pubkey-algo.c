/* t-pubkey-algo.c - Public-key algorithm mapping and description tests.
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <gpgme.h>

/* The mapper is private.  Link conversion.lo rather than exporting it.  */
extern int _gpgme_map_pk_algo (int algo, gpgme_protocol_t protocol);

static int
check_mapping (void)
{
  static const struct
  {
    int openpgp;
    gpgme_pubkey_algo_t family;
    const char *name;
  } tests[] = {
    { 1, GPGME_PK_RSA, "RSA" },
    { 2, GPGME_PK_RSA_E, "RSA-E" },
    { 3, GPGME_PK_RSA_S, "RSA-S" },
    { 8, GPGME_PK_KYBER, "KYBER" },
    { 16, GPGME_PK_ELG_E, "ELG-E" },
    { 17, GPGME_PK_DSA, "DSA" },
    { 18, GPGME_PK_ECDH, "ECDH" },
    { 19, GPGME_PK_ECDSA, "ECDSA" },
    { 20, GPGME_PK_ELG, "ELG" },
    { 22, GPGME_PK_EDDSA, "EdDSA" },
    { 25, GPGME_PK_ECDH, "ECDH" },
    { 27, GPGME_PK_EDDSA, "EdDSA" },
    { 30, GPGME_PK_MLDSA, "MLDSA" },
    { 31, GPGME_PK_MLDSA, "MLDSA" },
    { 32, GPGME_PK_SLHDSA, "SLHDSA" },
    { 33, GPGME_PK_SLHDSA, "SLHDSA" },
    { 34, GPGME_PK_SLHDSA, "SLHDSA" },
    { 35, GPGME_PK_MLKEM, "MLKEM" },
    { 36, GPGME_PK_MLKEM, "MLKEM" },
    { 37, GPGME_PK_MLKEM, "MLKEM" },
    { 38, GPGME_PK_MLKEM, "MLKEM" },
    { 39, GPGME_PK_MLKEM, "MLKEM" },
    { 40, GPGME_PK_MLKEM, "MLKEM" },
    { 41, 0, NULL },
    { 42, 0, NULL },
    { 43, 0, NULL },
    { 44, 0, NULL },
    { 0, 0, NULL },
    { 26, 0, NULL },
    { 28, 0, NULL },
    { 29, 0, NULL },
    { 45, 0, NULL },
    { 99, 0, NULL },
    { 128, 0, NULL },
    { 331, 0, NULL },
    { 332, 0, NULL },
    { 333, 0, NULL },
    { 334, 0, NULL },
    { -1, 0, NULL },
    { INT_MIN, 0, NULL },
    { INT_MAX, 0, NULL }
  };
  unsigned int i;
  const char *name;

  if (GPGME_PK_RSA != 1 || GPGME_PK_RSA_E != 2 || GPGME_PK_RSA_S != 3
      || GPGME_PK_KYBER != 8 || GPGME_PK_ELG_E != 16 || GPGME_PK_DSA != 17
      || GPGME_PK_ECC != 18 || GPGME_PK_ELG != 20 || GPGME_PK_ECDSA != 301
      || GPGME_PK_ECDH != 302 || GPGME_PK_EDDSA != 303
      || GPGME_PK_MLKEM != 331 || GPGME_PK_MLDSA != 332
      || GPGME_PK_SLHDSA != 334)
    return 1;

  for (i = 0; i < sizeof tests / sizeof tests[0]; i++)
    {
      errno = EDOM;
      if (_gpgme_map_pk_algo (tests[i].openpgp, GPGME_PROTOCOL_OPENPGP)
          != tests[i].family || errno != EDOM
          || _gpgme_map_pk_algo (tests[i].openpgp, GPGME_PROTOCOL_CMS)
             != tests[i].openpgp || errno != EDOM)
        {
          fprintf (stderr, "Wrong mapping for algorithm %d\n", tests[i].openpgp);
          return 1;
        }
      name = gpgme_pubkey_algo_name (tests[i].family);
      if (tests[i].name ? (!name || strcmp (name, tests[i].name)) : !!name)
        {
          fprintf (stderr, "Wrong family name for algorithm %d\n", tests[i].openpgp);
          return 1;
        }
    }
  return 0;
}

static int
check_description (void)
{
  static const unsigned int lengths[] = { 0, 128, 256, 4096 };
  static const char *const descriptions[] = { NULL, "", "backend-specific-text" };
  struct _gpgme_subkey subkey;
  unsigned int i, j;
  char *description;

  memset (&subkey, 0, sizeof subkey);
  subkey.pubkey_algo = GPGME_PK_SLHDSA;
  for (i = 0; i < sizeof lengths / sizeof lengths[0]; i++)
    for (j = 0; j < sizeof descriptions / sizeof descriptions[0]; j++)
      {
        subkey.length = lengths[i];
        subkey.curve = (char *) descriptions[j];
        description = gpgme_pubkey_algo_string (&subkey);
        if (!description || strcmp (description, "slhdsa"))
          {
            fprintf (stderr, "Wrong generic SLH-DSA description\n");
            gpgme_free (description);
            return 1;
          }
        gpgme_free (description);
      }
  return 0;
}

int
main (void)
{
  gpgme_check_version (NULL);
  if (check_mapping () || check_description ())
    return 1;
  return 0;
}
