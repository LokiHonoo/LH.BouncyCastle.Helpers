﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Utilities;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// Ed25519ctx.
    /// </summary>
    public sealed class Ed25519ctx : SignatureAlgorithm
    {
        #region Properties

        private readonly byte[] _context;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// Ed25519ctx.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        public Ed25519ctx() : this(Arrays.EmptyBytes)
        {
        }

        /// <summary>
        /// Ed25519ctx.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        public Ed25519ctx(byte[] context) : this(context, AsymmetricAlgorithmHelper.Ed25519)
        {
        }

        /// <summary>
        /// Ed25519ctx.
        /// <para/>Uses context byte[0] by default.
        /// </summary>
        /// <param name="context">Context.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public Ed25519ctx(byte[] context, IAsymmetricAlgorithm asymmetricAlgorithm) : base("Ed25519ctx", EnsureAlgorithm(asymmetricAlgorithm))
        {
            _context = context;
        }

        #endregion Constructor

        private protected override ISigner GenerateSigner()
        {
            return new Ed25519ctxSigner(_context);
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