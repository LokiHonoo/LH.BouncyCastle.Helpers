﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using System.Globalization;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// SM2.
    /// </summary>
    public sealed class SM2 : SignatureAlgorithm
    {
        #region Properties

        private readonly IHashAlgorithm _hashAlgorithm;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// SM2.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public SM2(IHashAlgorithm hashAlgorithm) : this(hashAlgorithm, AsymmetricAlgorithmHelper.SM2)
        {
        }

        /// <summary>
        /// SM2.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public SM2(IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withSM2", hashAlgorithm.Mechanism), EnsureAlgorithm(asymmetricAlgorithm))
        {
            _hashAlgorithm = hashAlgorithm;
        }

        #endregion Constructor

        private protected override ISigner GenerateSigner()
        {
            IDigest digest = _hashAlgorithm.GenerateDigest();
            return new SM2Signer(digest);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is null)
            {
                return AsymmetricAlgorithmHelper.SM2;
            }
            else if (asymmetricAlgorithm.Mechanism != "SM2")
            {
                throw new CryptographicException("Requires SM2 asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}