﻿using LH.BouncyCastle.Helpers.Security.Crypto.Symmetric;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Globalization;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Security.Crypto.Hash
{
    /// <summary>
    /// MAC.
    /// <para/>Legal mac size is between 8 and block size (8 bits increments).
    /// <para/>Legal mac size must be at least 24 bits (FIPS Publication 81) or 16 bits if being used as a data authenticator (FIPS Publication 113).
    /// <para/>Used (block size / 2) as mac size by default.
    /// </summary>
    public sealed class MAC : IMAC
    {
        #region Properties

        /// <summary>
        /// Gets block size bits.
        /// </summary>
        public int BlockSize => this.BlockAlgorithm.BlockSize;

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        public int HashSize { get; }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        public KeySizes[] KeySizes { get { return (KeySizes[])this.BlockAlgorithm.KeySizes.Clone(); } }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        public string Mechanism { get; }

        internal BlockAlgorithm BlockAlgorithm { get; }

        #endregion Properties

        #region Constructor

        /// <summary>
        /// MAC.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// <para/>Legal mac size must be at least 24 bits (FIPS Publication 81) or 16 bits if being used as a data authenticator (FIPS Publication 113).
        /// <para/>Used (block size / 2) as mac size by default.
        /// </summary>
        /// <param name="blockAlgorithm">Symmetric block algorithm.</param>
        public MAC(IBlockAlgorithm blockAlgorithm) : this(blockAlgorithm, blockAlgorithm.BlockSize / 2)
        {
        }

        /// <summary>
        /// MAC.
        /// <para/>Legal mac size is between 8 and block size (8 bits increments).
        /// <para/>Legal mac size must be at least 24 bits (FIPS Publication 81) or 16 bits if being used as a data authenticator (FIPS Publication 113).
        /// <para/>Used (block size / 2) as mac size by default.
        /// </summary>
        /// <param name="blockAlgorithm">Symmetric block algorithm.</param>
        /// <param name="macSize">MAC size bits.</param>
        public MAC(IBlockAlgorithm blockAlgorithm, int macSize)
        {
            if (macSize < 8 || macSize > blockAlgorithm.BlockSize || macSize % 8 != 0)
            {
                throw new CryptographicException("Legal mac size is between 8 and block size (8 bits increments).");
            }
            this.Mechanism = string.Format(CultureInfo.InvariantCulture, "{0}/MAC", blockAlgorithm.Mechanism);
            this.BlockAlgorithm = (BlockAlgorithm)blockAlgorithm;
            this.HashSize = macSize;
        }

        #endregion Constructor

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        public byte[] ComputeHash(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters, byte[] data)
        {
            return ComputeHash(mode, padding, parameters, data, 0, data.Length);
        }

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data buffer bytes.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] ComputeHash(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters, byte[] data, int offset, int length)
        {
            IMac digest = GenerateDigest(mode, padding, parameters);
            digest.BlockUpdate(data, offset, length);
            byte[] hash = new byte[this.HashSize];
            digest.DoFinal(hash, 0);
            return hash;
        }

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        public IMac GenerateDigest(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters)
        {
            IBlockCipherPadding pad;
            switch (padding)
            {
                case MACPaddingMode.NoPadding: pad = null; break;
                case MACPaddingMode.PKCS7: pad = Common.PKCS7Padding; break;
                case MACPaddingMode.Zeros: pad = Common.ZEROBYTEPadding; break;
                case MACPaddingMode.X923: pad = Common.X923Padding; break;
                case MACPaddingMode.ISO7816_4: pad = Common.ISO7816d4Padding; break;
                case MACPaddingMode.TBC: pad = Common.TBCPadding; break;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            IMac digest;
            switch (mode)
            {
                case MACCipherMode.CBC:
                    digest = pad is null ? new CbcBlockCipherMac(this.BlockAlgorithm.GenerateEngine(), this.HashSize)
                        : new CbcBlockCipherMac(this.BlockAlgorithm.GenerateEngine(), this.HashSize, pad);
                    break;

                case MACCipherMode.CFB:
                    int cfbs = ((ParametersWithIV)parameters).GetIV().Length * 8;
                    digest = pad is null ? new CfbBlockCipherMac(this.BlockAlgorithm.GenerateEngine(), cfbs, this.HashSize)
                        : new CfbBlockCipherMac(this.BlockAlgorithm.GenerateEngine(), cfbs, this.HashSize, pad);
                    break;

                default: throw new CryptographicException("Unsupported cipher mode.");
            }
            digest.Init(parameters);
            return digest;
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
            return this.BlockAlgorithm.GenerateParameters(key, iv);
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
            return this.BlockAlgorithm.GenerateParameters(key, keyOffset, keyLength, iv, ivOffset, ivLength);
        }

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return this.Mechanism;
        }

        /// <summary>
        /// Try get legal sizes.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="ivSizes">Legal iv size bits.</param>
        /// <returns></returns>
        public bool TryGetSizes(MACCipherMode mode, out KeySizes[] ivSizes)
        {
            switch (mode)
            {
                case MACCipherMode.CBC: ivSizes = new KeySizes[] { new KeySizes(this.BlockSize, this.BlockSize, 0) }; return true;
                case MACCipherMode.CFB: ivSizes = new KeySizes[] { new KeySizes(8, this.BlockSize, 8) }; return true;
                default: break;
            }
            ivSizes = null;
            return false;
        }
    }
}