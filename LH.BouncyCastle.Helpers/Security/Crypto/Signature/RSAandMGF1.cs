﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using System.Globalization;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Signature
{
    /// <summary>
    /// RSAandMGF1.
    /// </summary>
    public sealed class RSAandMGF1 : SignatureAlgorithm
    {
        #region Properties

        //private readonly IHashAlgorithm _hashAlgorithmContent;
        //private readonly int _saltLength;
        //private readonly byte _trailer = 0xBC;
        //private readonly byte[] _salt;
        private readonly IHashAlgorithm _hashAlgorithMgf;

        #endregion Properties

        #region Constructor

        /// <summary>
        /// RSAandMGF1.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        public RSAandMGF1(IHashAlgorithm hashAlgorithm) : this(hashAlgorithm, (IAsymmetricAlgorithm)AsymmetricAlgorithmHelper.RSA)
        {
        }

        /// <summary>
        /// RSAandMGF1.
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm.</param>
        /// <param name="asymmetricAlgorithm">Asymmetric algorithm. To provide function generate key pair, this argument is not required.</param>
        public RSAandMGF1(IHashAlgorithm hashAlgorithm, IAsymmetricAlgorithm asymmetricAlgorithm)
            : base(string.Format(CultureInfo.InvariantCulture, "{0}withRSAandMGF1", hashAlgorithm.Mechanism), EnsureAlgorithm(asymmetricAlgorithm))
        {
            _hashAlgorithMgf = hashAlgorithm;
        }

        #endregion Constructor
        private protected override ISigner GenerateSigner()
        {
            IDigest digest = _hashAlgorithMgf.GenerateDigest();
            return new PssSigner(new RsaBlindedEngine(), digest);
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