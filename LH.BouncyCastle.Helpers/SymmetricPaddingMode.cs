﻿namespace LH.BouncyCastle.Helpers
{
    /// <summary>
    /// Symmetric algorithm padding mode.
    /// </summary>
    public enum SymmetricPaddingMode
    {
        /// <summary>
        /// NoPadding padding mode.
        /// </summary>
        NoPadding = 1,

        /// <summary>
        /// PKCS7, PKCS5 padding mode.
        /// </summary>
        PKCS7,

        /// <summary>
        /// Warning: If the end of the plaintext is 0x00, it will be removed.
        /// </summary>
        Zeros,

        /// <summary>
        /// X923, ANSIX9.23 padding mode.
        /// </summary>
        X923,

        /// <summary>
        /// ISO10126, ISO10126_2 padding mode.
        /// </summary>
        ISO10126,

        /// <summary>
        /// ISO7816-4, ISO9797-1 padding mode.
        /// </summary>
        ISO7816_4 = 101,

        /// <summary>
        /// TBC padding mode.
        /// </summary>
        TBC,
    }
}