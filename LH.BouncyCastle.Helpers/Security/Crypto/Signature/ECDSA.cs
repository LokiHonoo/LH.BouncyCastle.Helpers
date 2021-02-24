﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System.Globalization;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// ECDSA.
    /// </summary>
    public sealed class ECDSA : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// ECDSA.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public ECDSA(IHashAlgorithm hashAlgorithm) : this(hashAlgorithm, AsymmetricAlgorithmHelper.ECDSA)
        {
        }

        /// <summary>
        /// ECDSA.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public ECDSA(IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withECDSA", hashAlgorithm.Mechanism), EnsureAlgorithm(asymmetricAlgorithm))
        {
            _hashAlgorithm = hashAlgorithm;
        }

        #endregion Constructor

        private protected override ISigner GenerateSigner()
        {
            IDigest digest = _hashAlgorithm.GenerateDigest();
            return new DsaDigestSigner(new ECDsaSigner(), digest);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is null)
            {
                return AsymmetricAlgorithmHelper.ECDSA;
            }
            else if (asymmetricAlgorithm.Mechanism != "ECDSA")
            {
                throw new System.Security.Cryptography.CryptographicException("Requires ECDSA asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}