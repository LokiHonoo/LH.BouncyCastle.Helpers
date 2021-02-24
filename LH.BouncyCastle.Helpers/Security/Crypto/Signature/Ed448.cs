﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed448.
    /// </summary>
    public sealed class Ed448 : SignatureAlgorithm
    {
        #region Properties

        private readonly byte[] _context;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Ed448.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        public Ed448() : this(Arrays.EmptyBytes)
        {
        }

        /// <summary>
        /// Ed448.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        public Ed448(byte[] context) : this(context, AsymmetricAlgorithmHelper.Ed448)
        {
        }

        /// <summary>
        /// Ed448.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public Ed448(byte[] context, IAsymmetricAlgorithm asymmetricAlgorithm) : base("Ed448", EnsureAlgorithm(asymmetricAlgorithm))
        {
            _context = context;
        }

        #endregion Constructor

        private protected override ISigner GenerateSigner()
        {
            return new Ed448Signer(_context);
        }

        private static IAsymmetricAlgorithm EnsureAlgorithm(IAsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is null)
            {
                return AsymmetricAlgorithmHelper.Ed448;
            }
            else if (asymmetricAlgorithm.Mechanism != "Ed448")
            {
                throw new System.Security.Cryptography.CryptographicException("Requires Ed448 asymmetric algorithm.");
            }
            else
            {
                return asymmetricAlgorithm;
            }
        }
    }
}