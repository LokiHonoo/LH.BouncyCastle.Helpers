﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Symmetric
{
    /// <summary>
    /// Symmetric stream algorithm.
    /// </summary>
    public abstract class StreamAlgorithm : SymmetricAlgorithm, IStreamAlgorithm
    {
        #region Properties

        private readonly KeySizes[] _ivSizes;
        private readonly KeySizes[] _keySizes;

        /// <summary>
        /// Gets legal iv size bits.
        /// </summary>
        public KeySizes[] IVSizes { get { return (KeySizes[])_ivSizes.Clone(); } }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public KeySizes[] KeySizes { get { return (KeySizes[])_keySizes.Clone(); } }

        #endregion Properties

        #region Constructor

        private protected StreamAlgorithm(string mechanism, KeySizes[] keySizes, KeySizes[] ivSizes) : base(mechanism)
        {
            _keySizes = keySizes;
            _ivSizes = ivSizes;
        }

        #endregion Constructor

        /// <summary>
        /// Generate cipher.
        /// </summary>
        /// <param name="forEncryption"></param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IBufferedCipher GenerateCipher(bool forEncryption, ICipherParameters parameters)
        {
            IStreamCipher engine = GenerateEngine();
            IBufferedCipher cipher = new BufferedStreamCipher(engine);
            cipher.Init(forEncryption, parameters);
            return cipher;
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="iv">IV bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key, byte[] iv)
        {
            return iv is null ? GenerateParameters(key, 0, key.Length, null, 0, 0) : GenerateParameters(key, 0, key.Length, iv, 0, iv.Length);
        }

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key buffer bytes.</param>
        /// <param name="keyOffset">The starting offset to read.</param>
        /// <param name="keyLength">The length to read.</param>
        /// <param name="iv">IV buffer bytes.</param>
        /// <param name="ivOffset">The starting offset to read.</param>
        /// <param name="ivLength">The length to read.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public ICipherParameters GenerateParameters(byte[] key, int keyOffset, int keyLength, byte[] iv, int ivOffset, int ivLength)
        {
            ICipherParameters parameters = new KeyParameter(key, keyOffset, keyLength);
            if (iv != null && ivLength > 0)
            {
                parameters = new ParametersWithIV(parameters, iv, ivOffset, ivLength);
            }
            return parameters;
        }

        private protected abstract IStreamCipher GenerateEngine();
    }
}