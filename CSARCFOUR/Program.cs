// Author(s): Michael Koeppl
//
// Implementation of the Arcfour cipher as described in:
// https://en.wikipedia.org/wiki/RC4

using System;
using System.Text;

namespace ConsoleApplication
{
    public class Program
    {
        // Implements the key-scheduling algorithm of RC4. This generates the
        // s-box (standard component of symmetric key algorithms) by first filling
        // an array with 0-255 and then swapping numbers as described in RC4.
        //
        // j is calculated ad (j + s[i] + key[i % keylength]), whereas i is
        // the index from 0 to 255.
        public static char[] KSA(char[] key)
        {
            char[] S = new char[256];
            for (int i = 0; i < 256; i++)
            {
                S[i] = (char)i;
            }

            var j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + key[i % key.Length]) % 256;
                var temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }
            return S;
        }

        // Implements the pseudo-random generation algorithm of RC4.
        // It utilizes i and j.
        // i is calculated as (i+1) % 256 in every iteration.
        // j is calculated as (j + s[i]) % 256 in every iteration.
        // The elements are then swapped and the output is
        // s[(s[i] + s[j]) % 256].
        public static char[] PRGA(byte[] key, char[] S)
        {
            char[] keystream = new char[256];
            int i = 0, j = 0;

            for (int x = 0; x < S.Length; x++)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                var temp = S[i];
                S[i] = S[j];
                S[j] = temp;
                keystream[i] = S[(S[i] + S[j]) % 256];
            }
            return keystream;
        }

        // This function is used to encrypt/decrypt text with the
        // given key and put the result in dest.
        // If text is an encrypted text, the output is plain text and vice versa.
        //
        // After the s-box and cipher been generated, text is bit-wise XOR'd with
        // the cipher.
        public static char[] Crypt(char[] text, char[] key)
        {
            char[] sbox = KSA(key);

            var keystream = PRGA(Encoding.ASCII.GetBytes(key), sbox);
            
            char[] resultText = new char[text.Length];
            for (int i = 0; i < text.Length; i++)
            {
                resultText[i] = (char)(text[i] ^ keystream[i]);
            }

            return resultText;
        }

        public static void Main(string[] args)
        {
            Console.Clear();

            string key = "pwd12";
            string text = "Hello, World!";

            var res = Crypt(text.ToCharArray(), key.ToCharArray());
            Console.WriteLine(res);

            var sres = Crypt(res, key.ToCharArray());
            Console.WriteLine(sres);
        }
    }
}
