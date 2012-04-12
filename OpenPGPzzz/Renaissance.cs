using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace OpenPGPzzz
{
    
    public class PgpEncryptionKeys
    {

        public PgpPublicKey PublicKey { get; private set; }

        public PgpPrivateKey PrivateKey { get; private set; }

        public PgpSecretKey SecretKey { get; private set; }

        public string PublicKeyPathd {get; private set;}
        public string PrivateKeyPathd { get; private set; }
        public string PassPhrase { get; private set; }

        /// <summary>

        /// Initializes a new instance of the EncryptionKeys class.

        /// Two keys are required to encrypt and sign data. Your private key and the recipients public key.

        /// The data is encrypted with the recipients public key and signed with your private key.

        /// </summary>

        /// <param name="publicKeyPath">The key used to encrypt the data</param>

        /// <param name="privateKeyPath">The key used to sign the data.</param>

        /// <param name="passPhrase">The (your) password required to access the private key</param>

        /// <exception cref="ArgumentException">Public key not found. Private key not found. Missing password</exception>

        public PgpEncryptionKeys(string publicKeyPath, string privateKeyPath, string passPhrase)
        {
            this.PrivateKeyPathd = privateKeyPath;

            this.PublicKeyPathd = publicKeyPath;

            this.PassPhrase = passPhrase;

            if (!File.Exists(publicKeyPath))

                throw new ArgumentException("Public key file not found", "publicKeyPath");

            if (!File.Exists(privateKeyPath))

                throw new ArgumentException("Private key file not found", "privateKeyPath");

            if (String.IsNullOrEmpty(passPhrase))

                throw new ArgumentException("passPhrase is null or empty.", "passPhrase");

            PublicKey = ReadPublicKey(publicKeyPath);

            SecretKey = ReadSecretKey(privateKeyPath);

            PrivateKey = ReadPrivateKey(passPhrase);

        }

        #region Secret Key

        private PgpSecretKey ReadSecretKey(string privateKeyPath)
        {

            using (Stream keyIn = File.OpenRead(privateKeyPath))

            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {

                PgpSecretKeyRingBundle secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);

                PgpSecretKey foundKey = GetFirstSecretKey(secretKeyRingBundle);

                if (foundKey != null)

                    return foundKey;

            }

            throw new ArgumentException("Can't find signing key in key ring.");

        }

        /// <summary>

        /// Return the first key we can use to encrypt.

        /// Note: A file can contain multiple keys (stored in "key rings")

        /// </summary>

        private PgpSecretKey GetFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {

            foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
            {

                PgpSecretKey key = kRing.GetSecretKeys()

                    .Cast<PgpSecretKey>()

                    .Where(k => k.IsSigningKey)

                    .FirstOrDefault();

                if (key != null)

                    return key;

            }

            return null;

        }

        #endregion

        #region Public Key

        private PgpPublicKey ReadPublicKey(string publicKeyPath)
        {

            using (Stream keyIn = File.OpenRead(publicKeyPath))

            using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
            {

                PgpPublicKeyRingBundle publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);

                PgpPublicKey foundKey = GetFirstPublicKey(publicKeyRingBundle);

                if (foundKey != null)

                    return foundKey;

            }

            throw new ArgumentException("No encryption key found in public key ring.");

        }

        private PgpPublicKey GetFirstPublicKey(PgpPublicKeyRingBundle publicKeyRingBundle)
        {

            foreach (PgpPublicKeyRing kRing in publicKeyRingBundle.GetKeyRings())
            {

                PgpPublicKey key = kRing.GetPublicKeys()

                    .Cast<PgpPublicKey>()

                    .Where(k => k.IsEncryptionKey)

                    .FirstOrDefault();

                if (key != null)

                    return key;

            }

            return null;

        }

        #endregion

        #region Private Key

        private PgpPrivateKey ReadPrivateKey(string passPhrase)
        {

            PgpPrivateKey privateKey = SecretKey.ExtractPrivateKey(passPhrase.ToCharArray());

            if (privateKey != null)

                return privateKey;

            throw new ArgumentException("No private key found in secret key.");

        }

        #endregion

    }

    public class PgpDecrypt
    {
        
        private PgpEncryptionKeys m_encryptionKeys;
        

        private const int BufferSize = 0x10000; // should always be power of 2 

        /// <summary>

        /// Instantiate a new PgpEncrypt class with initialized PgpEncryptionKeys.

        /// </summary>

        /// <param name="encryptionKeys"></param>

        /// <exception cref="ArgumentNullException">encryptionKeys is null</exception>

        public PgpDecrypt(PgpEncryptionKeys encryptionKeys)
        {
            if (encryptionKeys == null)
                throw new ArgumentNullException("encryptionKeys", "encryptionKeys is null.");

            m_encryptionKeys = encryptionKeys;
        }
        private PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyID, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyID);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }
       
        public void VerifySignature(Stream input, string outputpath)
        {
            input = PgpUtilities.GetDecoderStream(input);
            PgpObjectFactory pgpObjF = new PgpObjectFactory(input);            
            
            PgpEncryptedDataList enc = (PgpEncryptedDataList) pgpObjF.NextPgpObject();
            
            PgpPrivateKey sKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.
                GetDecoderStream(File.OpenRead(m_encryptionKeys.PrivateKeyPathd)));
            
            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                sKey = FindSecretKey(pgpSec, pked.KeyId, m_encryptionKeys.PassPhrase.ToCharArray());

                if (sKey != null)
                {
                    pbe = pked;
                    break;
                }
            }

            if (sKey == null)
            {
                throw new ArgumentException("secret key for message not found.");
            }
            
            Stream clear = pbe.GetDataStream(sKey);
            PgpObjectFactory plainFact = new PgpObjectFactory(clear);
            PgpCompressedData cData = (PgpCompressedData)plainFact.NextPgpObject();
            PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());
            PgpObject message = pgpFact.NextPgpObject();

            if (message is PgpOnePassSignatureList)
            {
                PgpOnePassSignatureList p1 = (PgpOnePassSignatureList)message;
                PgpOnePassSignature ops = p1[0];

                PgpLiteralData p2 = (PgpLiteralData)pgpFact.NextPgpObject();
                Stream dIn = p2.GetInputStream();

                PgpPublicKeyRingBundle pgpRing = new PgpPublicKeyRingBundle(PgpUtilities.
                            GetDecoderStream(File.OpenRead(m_encryptionKeys.PublicKeyPathd)));
                PgpPublicKey key = pgpRing.GetPublicKey(ops.KeyId);

                
                Stream fos = File.Create(p2.FileName);
                ops.InitVerify(key);

                int ch;
                while ((ch = dIn.ReadByte()) >= 0)
                {
                    ops.Update((byte)ch);
                    fos.WriteByte((byte)ch);
                }
                fos.Close();
                
                //PgpObject p3 = pgpFact.NextPgpObject();
                //if(p3 is PgpSignature)
                //    throw new PgpException("signature verified.");
                PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
                PgpSignature firstSig = p3[0];
                if (ops.Verify(firstSig))
                {

                    throw new PgpException("signature verified.");
                }
                else
                {

                    throw new PgpException("signature verification failed.");
                }

            }
            
            

        }

       

       
    }

    /// <summary>

    /// Wrapper around Bouncy Castle OpenPGP library.

    /// Bouncy documentation can be found here: http://www.bouncycastle.org/docs/pgdocs1.6/index.html

    /// </summary>

    public class PgpEncrypt
    {

        private PgpEncryptionKeys m_encryptionKeys;

        private const int BufferSize = 0x10000; // should always be power of 2 

        /// <summary>

        /// Instantiate a new PgpEncrypt class with initialized PgpEncryptionKeys.

        /// </summary>

        /// <param name="encryptionKeys"></param>

        /// <exception cref="ArgumentNullException">encryptionKeys is null</exception>

        public PgpEncrypt(PgpEncryptionKeys encryptionKeys)
        {

            if (encryptionKeys == null)

                throw new ArgumentNullException("encryptionKeys", "encryptionKeys is null.");

            m_encryptionKeys = encryptionKeys;

        }

        /// <summary>

        /// Encrypt and sign the file pointed to by unencryptedFileInfo and

        /// write the encrypted content to outputStream.

        /// </summary>

        /// <param name="outputStream">The stream that will contain the

        /// encrypted data when this method returns.</param>

        /// <param name="fileName">FileInfo of the file to encrypt</param>

        public void EncryptAndSign(Stream outputStream, FileInfo unencryptedFileInfo)
        {

            if (outputStream == null)
                throw new ArgumentNullException("outputStream", "outputStream is null.");

            if (unencryptedFileInfo == null)
                throw new ArgumentNullException("unencryptedFileInfo", "unencryptedFileInfo is null.");

            if (!File.Exists(unencryptedFileInfo.FullName))
                throw new ArgumentException("File to encrypt not found.");

            Encoding enc = DetectEncoding(unencryptedFileInfo.FullName);
            string name = enc.EncodingName;

            using (Stream encryptedOut = ChainEncryptedOut(outputStream))
            using (Stream compressedOut = ChainCompressedOut(encryptedOut))
            {

                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);

                using (Stream literalOut = ChainLiteralOut(compressedOut, unencryptedFileInfo))
                using (FileStream inputFile = unencryptedFileInfo.OpenRead())                
                {
                    StreamReader strRdr = new StreamReader(inputFile);
                    Encoding code = strRdr.CurrentEncoding;
                    WriteOutputAndSign(compressedOut, literalOut, inputFile, signatureGenerator);
                }

            }

        }

        public Encoding DetectEncoding(String fileName)
        {
            // open the file with the stream-reader:
            using (StreamReader reader = new StreamReader(fileName, true))
            {
                
                // return the encoding.
                return reader.CurrentEncoding;
            }
        }


        private static void WriteOutputAndSign( Stream compressedOut,
                                                Stream literalOut,
                                            FileStream inputFile,
                                 PgpSignatureGenerator signatureGenerator){

            
            int length = 0;
            byte[] buf = new byte[BufferSize];
            while ((length = inputFile.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }
            
            signatureGenerator.Generate().Encode(compressedOut);
        }

        private Stream ChainEncryptedOut(Stream outputStream)
        {
            PgpEncryptedDataGenerator encryptedDataGenerator;
            encryptedDataGenerator =  new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.TripleDes,new SecureRandom());
            encryptedDataGenerator.AddMethod(m_encryptionKeys.PublicKey);
            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
        }

        private static Stream ChainCompressedOut(Stream encryptedOut)
        {
            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            return compressedDataGenerator.Open(encryptedOut);
        }

        private static Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, PgpLiteralData.Binary, file);
        }

        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
        {
            const bool IsCritical = false;
            const bool IsNested = false;
            PublicKeyAlgorithmTag tag = m_encryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha1);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, m_encryptionKeys.PrivateKey);

            foreach (string userId in m_encryptionKeys.SecretKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.SetSignerUserId(IsCritical, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());

                // Just the first one!
                break;
            }

            pgpSignatureGenerator.GenerateOnePassVersion(IsNested).Encode(compressedOut);

            return pgpSignatureGenerator;

        }
    }
}
