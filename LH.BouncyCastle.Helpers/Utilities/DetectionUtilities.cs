﻿using System.Security.Cryptography;

namespace LH.BouncyCastle.Helpers.Utilities
{
    internal static class DetectionUtilities
    {
        internal static bool ValidSize(KeySizes[] sizes, int size)
        {
            foreach (KeySizes available in sizes)
            {
                if (available.SkipSize == 0)
                {
                    if (size == available.MinSize)
                    {
                        return true;
                    }
                }
                else if (size >= available.MinSize && size <= available.MaxSize && size % available.SkipSize == 0)
                {
                    return true;
                }
            }
            return false;
        }
    }
}