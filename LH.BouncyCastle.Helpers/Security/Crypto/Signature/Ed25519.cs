﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed25519.
    /// </summary>
    public sealed class Ed25519 : SignatureAlgorithm
    {
        #region Constructor

        /// <summary>
        /// Ed25519.
        /// </summary>
        public Ed25519() : this(AsymmetricAlgorithmHelper.Ed25519)
        {
        }

        /// <summary>
        /// Ed25519.
        /// </summary>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public Ed25519(IAsymmetricAlgorithm asymmetricAlgorithm) : base("Ed25519", EnsureAlgorithm(asymmetricAlgorithm))
        {
        }

        #endregion Constructor

        private protected override ISigner GenerateSigner()
        {
            return new Ed25519Signer();
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is null)
            {
                return AsymmetricAlgorithmHelper.Ed25519;
            }
            else if (asymmetricAlgorithm.Mechanism != "Ed25519")
            {
                throw new System.Security.Cryptography.CryptographicException("Requires Ed25519 asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}