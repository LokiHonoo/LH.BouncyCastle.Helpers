﻿using Org.BouncyCastle.Crypto;
using System;
using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric block algorithm interface.
    /// </summary>
    public interface IBlockAlgorithm
    {
        /// <summary>
        /// Gets block size bits.
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Gets legal key size bits.
        /// </summary>
        KeySizes[] KeySizes { get; }

        /// <summary>
        /// Gets mechanism.
        /// </summary>
        string Mechanism { get; }

        /// <summary>
        /// Generate cipher. The cipher can be reused. Except GCM cipher mode.
        /// </summary>
        /// <param name="forEncryption"></param>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="parameters">Parameters.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>

        IBufferedCipher GenerateCipher(bool forEncryption, SymmetricCipherMode mode, SymmetricPaddingMode padding, ICipherParameters parameters);

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
        /// Generate parameters.
        /// </summary>
        /// <param name="key">Key bytes.</param>
        /// <param name="nonce">Nonce bytes.</param>
        /// <param name="macSize">MAC size bits.</param>
        /// <param name="associatedText">Associated text bytes.</param>
        /// <returns></returns>
        /// <exception cref="Exception"/>
        ICipherParameters GenerateParameters(byte[] key, byte[] nonce, int macSize, byte[] associatedText);

        /// <summary>
        /// Return mechanism.
        /// </summary>
        /// <returns></returns>
        string ToString();

        /// <summary>
        /// Try get legal sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="ivSizes">Legal iv size bits.</param>
        /// <returns></returns>
        bool TryGetSizes(SymmetricCipherMode mode, SymmetricPaddingMode padding, out KeySizes[] ivSizes);

        /// <summary>
        /// Try get legal sizes.
        /// </summary>
        /// <param name="mode">Symmetric algorithm cipher mode.</param>
        /// <param name="padding">Symmetric algorithm padding mode.</param>
        /// <param name="nonceSizes">Legal nonce size bits.</param>
        /// <param name="macSizes">Legal mac size bits.</param>
        /// <returns></returns>
        bool TryGetSizes(SymmetricCipherMode mode, SymmetricPaddingMode padding, out KeySizes[] nonceSizes, out KeySizes[] macSizes);
    }
}