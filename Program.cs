namespace Timelock
{
    using System;
    using System.Text;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Engines;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Modes;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Security;

    public class Program
    {
        public static void Main(string[] args)
        {
            switch (args.Length > 0 ? args[0] : "")
            {
                case "encrypt":
                {
                    Console.Write("Enter the A value: ");
                    var a = Console.ReadLine() ??
                        throw new ArgumentException("A must not be null");
                    Console.Write("Enter the T value: ");
                    var t = Console.ReadLine() ??
                        throw new ArgumentException("T must not be null");

                    EncryptFile(args[1], args[2], a, t);
                    break;
                }
                case "decrypt":
                {
                    Console.Write("Enter the A value: ");
                    var a = Console.ReadLine() ??
                        throw new ArgumentException("A must not be null");
                    Console.Write("Enter the CK value: ");
                    var ck = Console.ReadLine() ??
                        throw new ArgumentException("CK must not be null");
                    Console.Write("Enter the T value: ");
                    var t = Console.ReadLine() ??
                        throw new ArgumentException("T must not be null");
                    Console.Write("Enter the Modulus value: ");
                    var modulus = Console.ReadLine() ??
                        throw new ArgumentException("Modulus must not be null");

                    DecryptFile(args[1], args[2], a, ck, t, modulus);
                    break;
                }
                default:
                {
                    // I'll break my rule, this one time, for the road.
                    Console.WriteLine("timelock - simple timelock-based encryption tool");
                    Console.WriteLine("\ttimelock encrypt <input filename> <output filename>");
                    Console.WriteLine("\t\t encrypts a file, asks for public variables via STDIN, produces all public variables to distribute to STDOUT.");
                    Console.WriteLine("\ttimelock decrypt <input filename> <output filename>");
                    Console.WriteLine("\t\t decrypts a file, asks for public variables via STDIN.");
                    break;
                }
            }
        }

        public static void EncryptFile(
            string inputFile,
            string outputFile,
            string preA,
            string t)
        {
            var generator = new RsaKeyPairGenerator();
            var defaultPublicExponent = BigInteger.ValueOf(0x10001);
            var random = new SecureRandom();
            var param = new RsaKeyGenerationParameters(
                defaultPublicExponent,
                random,
                4096,
                4096);
            generator.Init(param);
            var pair = generator.GenerateKeyPair();
            var privKey = pair.Private as RsaPrivateCrtKeyParameters;
            Console.Write("Modulus: ");
            Console.WriteLine(privKey!.Modulus.ToString());

            var digest = new Sha3Digest();
            var message = Encoding.UTF8.GetBytes(preA);
            digest.BlockUpdate(message, 0, message.Length);
            
            // Ensure this is always read as a positive integer:
            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            var a = new BigInteger(1, hash);
            var shortcut = a.ModPow(
                BigInteger.Two.ModPow(
                    new BigInteger(t),
                    (privKey.P.Subtract(BigInteger.One)).Multiply(
                        privKey.Q.Subtract(BigInteger.One))
                ), privKey.Modulus);

            var key = new byte[digest.GetDigestSize()];
            random.NextBytes(key);
            var ck = shortcut.Add(new BigInteger(1, key)).Mod(privKey.Modulus);
            Console.Write("CK: ");
            Console.WriteLine(ck.ToString());
            
            var iv = new byte[12];
            random.NextBytes(iv);
            var cipher = new GcmBlockCipher(new AesEngine());
            var cipherParam = new AeadParameters(
                new KeyParameter(key),
                128,
                iv,
                hash);
            cipher.Init(true, cipherParam);

            var plaintext = File.ReadAllBytes(inputFile);
            var outputBytes = new byte[cipher.GetOutputSize(plaintext.Length)];
            var length = cipher.ProcessBytes(
                plaintext,
                0,
                plaintext.Length,
                outputBytes,
                0);
            cipher.DoFinal(outputBytes, length);
            
            File.WriteAllBytes(outputFile, iv.Concat(outputBytes).ToArray());
            Console.WriteLine("File written.");
        }

        public static void DecryptFile(
            string inputFile,
            string outputFile,
            string preA,
            string ck,
            string t,
            string modulus)
        {
            var digest = new Sha3Digest();
            var message = Encoding.UTF8.GetBytes(preA);
            digest.BlockUpdate(message, 0, message.Length);
            
            // Ensure this is always read as a positive integer:
            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            var a = new BigInteger(1, hash);
            var mod = new BigInteger(modulus);

            for (
                var i = BigInteger.Zero;
                i.CompareTo(new BigInteger(t)) < 0;
                i = i.Add(BigInteger.One))
            {
                a = a.ModPow(BigInteger.Two, mod);
            }

            var deckey = new BigInteger(ck).Subtract(a).Mod(mod);
            var key = new byte[digest.GetDigestSize()];
            key = deckey.ToByteArrayUnsigned();
            var input = File.ReadAllBytes(inputFile);
            var iv = input.Take(12).ToArray();
            var ciphertext = input.Skip(12).ToArray();
            var cipher = new GcmBlockCipher(new AesEngine());
            var cipherParam = new AeadParameters(
                new KeyParameter(key),
                128,
                iv,
                hash);
            cipher.Init(false, cipherParam);

            var plaintext = new byte[ciphertext.Length];
            var length = cipher.ProcessBytes(
                ciphertext,
                0,
                ciphertext.Length,
                plaintext,
                0);
            cipher.DoFinal(plaintext, length);
            File.WriteAllBytes(outputFile, plaintext);
            Console.WriteLine("see you space cowgirl...");
        }
    }
}