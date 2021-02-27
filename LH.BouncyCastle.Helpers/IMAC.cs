﻿using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers
{
    /// <summary>
    /// MAC interface.
    /// </summary>
    public interface IMAC
    {
        /// <summary>
        /// Gets block size bits.
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Gets hash size bits.
        /// </summary>
        int HashSize { get; }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        KeySizes[] KeySizes { get; }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Generate a new digest and compute data hash.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <param name="data">Data bytes.</param>
        /// <returns></returns>
        byte[] ComputeHash(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters, byte[] data);

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
        byte[] ComputeHash(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters, byte[] data, int offset, int length);

        /// <summary>
        /// Generate digest. The digest can be reused.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="padding">MAC padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        IMac GenerateDigest(MACCipherMode mode, MACPaddingMode padding, ICipherParameters parameters);

        /// <summary>
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="iv">IV bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] key, byte[] iv);

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
        ICipherParameters GenerateParameters(byte[] key, int keyOffset, int keyLength, byte[] iv, int ivOffset, int ivLength);

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();

        /// <summary>
        /// Try get legal sizes.
        /// </summary>
        /// <param name="mode">MAC cipher mode.</param>
        /// <param name="ivSizes">Legal iv size bits.</param>
        /// <returns></returns>
        bool TryGetSizes(MACCipherMode mode, out KeySizes[] ivSizes);
    }
}