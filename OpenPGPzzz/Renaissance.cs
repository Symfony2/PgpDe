using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using System.Collections;

namespace OpenPGPzzz
{

    #region Encryption keys storage
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
    #endregion

    #region Decryption class
    public class PgpDecrypt
    {
        
        private PgpEncryptionKeys m_encryptionKeys;
        

        private const int BufferSize = 0x11000; // should always be power of 2 

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

            //IList collection = pgpObjF.AllPgpObjects();
            
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
    #endregion

    #region Encrypt class first try
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

            

            using (Stream encryptedOut = ChainEncryptedOut(outputStream))
            using (Stream compressedOut = ChainCompressedOut(encryptedOut))
            {

                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                using (Stream literalOut = ChainLiteralOut(compressedOut, unencryptedFileInfo))
                using (FileStream inputFile = unencryptedFileInfo.OpenRead())                
                {
                    WriteOutputAndSign(compressedOut, literalOut, inputFile, signatureGenerator);
                }
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
            string fileName = PgpLiteralData.Console;
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, PgpLiteralData.Binary,file);
        }

        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
        {
            const bool IsCritical = false;
            const bool IsNested = false;
            PublicKeyAlgorithmTag tag = m_encryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha384);
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
    #endregion

   /* #region Second version of enc

    public class PGPencryption
    {
        public string EncryptAndSign(string input, string recipientPublicKeyPath, string senderPrivateKeyPath, string passPhrase) 
	        { 
	 
	            //get data to encrypt 
	            byte[] clearData = Encoding.ASCII.GetBytes(input); 
	 
	            //create memory stream to hold output from encryption 
	            MemoryStream finalOut = new MemoryStream(); 
	 
	            //enclide output in ascii armour (i.e. base 64 encode) so definietly can be sent over plain text email 
	            ArmoredOutputStream armouredOut = new ArmoredOutputStream(finalOut); 
	 
	            //get public key to encrypt message 
	            PgpPublicKey encryptionKey = this.ReadPublicKey(recipientPublicKeyPath); 
	 
	            //initialise encrypted data generator 
	            PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, new SecureRandom()); 
	            encryptedDataGenerator.AddMethod(encryptionKey); 
	            Stream encOut = encryptedDataGenerator.Open(armouredOut, clearData.Length); 
	 
	 
	            //initialise compression 
	            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip); 
	            Stream compressedOut = compressedDataGenerator.Open(encOut); 
	 
	 
	 
	            //get signing key (secret key = private key with pass-phrase protection 
	            PgpSecretKey pgpSecKey = ReadSecretKey(senderPrivateKeyPath); 
	            //get actual private key to use by unlocaking with pass-phrase 
	            PgpPrivateKey signingPrivateKey = pgpSecKey.ExtractPrivateKey(passPhrase.ToCharArray()); 
	 
	            //initialise signature generator 
	            PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1); 
	             
	            signatureGenerator.InitSign(PgpSignature.CanonicalTextDocument, signingPrivateKey); 
	            PgpSignatureSubpacketGenerator subpacketGenerator = new PgpSignatureSubpacketGenerator(); 
	            System.Collections.IEnumerator enumerator = pgpSecKey.PublicKey.GetUserIds().GetEnumerator(); 
	            if (enumerator.MoveNext()) 
	            { 
	                subpacketGenerator.SetSignerUserId(false, (string)enumerator.Current); 
	                signatureGenerator.SetHashedSubpackets(subpacketGenerator.Generate()); 
	            } 
	            PgpOnePassSignature onePassSignature = signatureGenerator.GenerateOnePassVersion(false); 
	            onePassSignature.Encode(compressedOut); 
	 
	            // Create the Literal Data generator Output stream which writes to the compression stream 
	            string fileName = PgpLiteralData.Console; 
	 
	            PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator(); 
	            Stream literalOut = literalDataGenerator.Open(compressedOut, // the compressed output stream 
	                                                    PgpLiteralData.Binary, 
	                                                    fileName,    // "filename" to store 
	                                                    clearData.Length,  // length of clear data 
	                                                    DateTime.UtcNow   // current time 
	                                                    ); 
	 
	 
	            //write data to output stream (eventually - goes through literal stream, compression stream, and encryption stream on the way!) 
	            literalOut.Write(clearData, 0, clearData.Length); 
	 
	            //update signature generator with data 
	            signatureGenerator.Update(clearData, 0, clearData.Length); 
	 
	            //close literal output 
	            literalOut.Close(); 
	            literalDataGenerator.Close(); 
	 
	 
	            //generate signature and send to output stream 
	            signatureGenerator.Generate().Encode(compressedOut); 
	            //close other output streams 
	            compressedOut.Close(); 
	            compressedDataGenerator.Close(); 
	            encOut.Close(); 
	            encryptedDataGenerator.Close(); 
	            armouredOut.Close(); 
	            finalOut.Close(); 
	            return Encoding.ASCII.GetString(finalOut.ToArray()); 
	 
	        } 
	 
	        private PgpSecretKey ReadSecretKey(string senderPrivateKeyPath) 
	        { 
	 
	            Stream keyIn = File.OpenRead(senderPrivateKeyPath); 
	            Stream inputStream = PgpUtilities.GetDecoderStream(keyIn); 
	            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(inputStream); 
	            inputStream.Close(); 
	            keyIn.Close(); 
	 
	            // just loop through the collection till we find a key suitable for encryption 
	            // assuming only one key in there 
	 
	            foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings()) 
	            { 
	                foreach (PgpSecretKey k in kRing.GetSecretKeys()) 
	                { 
	                    if (k.IsSigningKey) 
	                    { 
	                        return k; 
	                    } 
	                } 
	            } 
	 
	            throw new ArgumentException("Can't find signing key in key ring."); 
	        } 
	 
	        private PgpPublicKey ReadPublicKey(string publicKeyPath) 
	        { 
	            Stream keyIn = File.OpenRead(publicKeyPath); 
	            Stream inputStream = PgpUtilities.GetDecoderStream(keyIn); 
	            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream); 
	            inputStream.Close(); 
	            keyIn.Close(); 
	 
	            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings()) 
	            { 
	                foreach (PgpPublicKey k in kRing.GetPublicKeys()) 
	                { 
	                    if (k.IsEncryptionKey) 
	                    { 
	                        return k; 
	                    } 
	                } 
	            } 
	            throw new ArgumentException("Can't find encryption key in key ring."); 
	        } 
    }

    #endregion*/

}
