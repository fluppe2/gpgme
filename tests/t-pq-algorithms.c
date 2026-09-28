/* t-pq-algorithms.c - Regression test for PQ algorithm families.
 * Copyright (C) 2026 g10 Code GmbH
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
 * License along with GPGME; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gpgme.h>


static void
fail (const char *what, const char *value, const char *expected)
{
  fprintf (stderr, "%s: got '%s', expected '%s'\n",
           what, value? value : "(null)", expected? expected : "(null)");
  exit (1);
}


static void
check_algo_name (gpgme_pubkey_algo_t algo, int value, const char *name)
{
  const char *result = gpgme_pubkey_algo_name (algo);

  if (algo != value)
    {
      char actual[16];
      char expected[16];

      snprintf (actual, sizeof actual, "%d", algo);
      snprintf (expected, sizeof expected, "%d", value);
      fail ("algo value", actual, expected);
    }
  if (!result || strcmp (result, name))
    fail ("algo name", result, name);
}


static void
check_algo_string (gpgme_pubkey_algo_t algo, const char *curve)
{
  struct _gpgme_subkey subkey;
  char *result;

  memset (&subkey, 0, sizeof subkey);
  subkey.pubkey_algo = algo;
  subkey.curve = (char *)curve;

  result = gpgme_pubkey_algo_string (&subkey);
  if (!result || strcmp (result, curve))
    fail ("algo string", result, curve);
  gpgme_free (result);
}


int
main (void)
{
  static struct
  {
    gpgme_pubkey_algo_t algo;
    int value;
    const char *name;
  }
  algo_names[] =
    {
      { GPGME_PK_MLKEM, 331, "MLKEM" },
      { GPGME_PK_MLDSA, 332, "MLDSA" },
      { GPGME_PK_SLHDSA, 333, "SLHDSA" }
    };
  static struct
  {
    gpgme_pubkey_algo_t algo;
    const char *curve;
  }
  algo_strings[] =
    {
      { GPGME_PK_MLDSA, "ML-DSA-65+Ed25519" },
      { GPGME_PK_MLDSA, "ML-DSA-87+Ed448" },
      { GPGME_PK_SLHDSA, "SLH-DSA-SHAKE-128s" },
      { GPGME_PK_SLHDSA, "SLH-DSA-SHAKE-128f" },
      { GPGME_PK_SLHDSA, "SLH-DSA-SHAKE-256s" },
      { GPGME_PK_MLKEM, "ML-KEM-768+X25519" },
      { GPGME_PK_MLKEM, "ML-KEM-1024+X448" },
      { GPGME_PK_MLKEM, "ML-KEM-768+ECDH-NIST-P-384" },
      { GPGME_PK_MLKEM, "ML-KEM-1024+ECDH-NIST-P-521" },
      { GPGME_PK_MLKEM, "ML-KEM-768+ECDH-brainpoolP384r1" },
      { GPGME_PK_MLKEM, "ML-KEM-1024+ECDH-brainpoolP512r1" },
      { GPGME_PK_MLDSA, "ML-DSA-65+ECDSA-NIST-P-384" },
      { GPGME_PK_MLDSA, "ML-DSA-87+ECDSA-NIST-P-521" },
      { GPGME_PK_MLDSA, "ML-DSA-65+ECDSA-brainpoolP384r1" },
      { GPGME_PK_MLDSA, "ML-DSA-87+ECDSA-brainpoolP512r1" },
      { GPGME_PK_MLKEM, "mlk768_bp384" },
      { GPGME_PK_MLKEM, "mlk1024_x448" }
    };
  size_t idx;

  gpgme_check_version (NULL);

  for (idx = 0; idx < sizeof algo_names / sizeof algo_names[0]; idx++)
    check_algo_name (algo_names[idx].algo,
                     algo_names[idx].value, algo_names[idx].name);

  for (idx = 0; idx < sizeof algo_strings / sizeof algo_strings[0]; idx++)
    check_algo_string (algo_strings[idx].algo, algo_strings[idx].curve);

  return 0;
}
