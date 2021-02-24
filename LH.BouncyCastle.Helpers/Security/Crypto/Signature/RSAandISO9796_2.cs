﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using System.Globalization;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// RSA/ISO9796-2.
    /// </summary>
    public sealed class RSAandISO9796_2 : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// RSA/ISO9796-2.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public RSAandISO9796_2(IHashAlgorithm hashAlgorithm) : this(hashAlgorithm, (IAsymmetricAlgorithm)AsymmetricAlgorithmHelper.RSA)
        {
        }

        /// <summary>
        /// RSA/ISO9796-2.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public RSAandISO9796_2(IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withISO9796-2", hashAlgorithm.Mechanism), EnsureAlgorithm(asymmetricAlgorithm))
        {
            _hashAlgorithm = hashAlgorithm;
        }

        #endregion Constructor

        private protected override ISigner GenerateSigner()
        {
            IDigest digest = _hashAlgorithm.GenerateDigest();
            return new Iso9796d2Signer(new RsaBlindedEngine(), digest, true);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is null)
            {
                return (IAsymmetricAlgorithm)AsymmetricAlgorithmHelper.RSA;
            }
            else if (asymmetricAlgorithm.Mechanism != "RSA")
            {
                throw new System.Security.Cryptography.CryptographicException("Requires RSA asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}