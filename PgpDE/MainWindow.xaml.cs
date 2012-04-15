using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using OpenPGPzzz;

namespace PgpDE 
    
    /*OPen debug\bin directory during the program run and u ll see that encryption/decryption works fine but verifing doesn't work
     many thanks !!!*/
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string publicKeyPath;
        private string privateKeyPath;
        private string passPhrase;
        private string filePath;
        private string hashTypeName;

        public MainWindow()
        {
            InitializeComponent();

            //recivers public key
            publicKeyPath = Environment.CurrentDirectory + @"\keys\reciver\pub.bpg";
            //senders private key
            privateKeyPath = Environment.CurrentDirectory + @"\keys\sender\secret.bpg";
            //pass phrase
            passPhrase = "galileo";
            
        }

        private void button1_Click(object sender, RoutedEventArgs e)
        {
            //recivers public key
            publicKeyPath = Environment.CurrentDirectory + @"\keys\reciver\pub.bpg";
            //senders private key
            privateKeyPath = Environment.CurrentDirectory + @"\keys\sender\secret.bpg";
            //pass phrase
            passPhrase = "galileo";

            PgpEncryptionKeys kes = new PgpEncryptionKeys(this.publicKeyPath, this.privateKeyPath, this.passPhrase);
            PgpEncrypt ecnFile = new PgpEncrypt(kes);
            FileInfo fileInfo = new FileInfo(Environment.CurrentDirectory + @"\exp\tty.doc");

            string path = Environment.CurrentDirectory + "\\" + fileInfo.Name + ".pgp";
            
            using (Stream outStrm = File.Create(path))
            {                
                ecnFile.EncryptAndSign(outStrm, fileInfo);                
            }
            
        }

        private void button2_Click(object sender, RoutedEventArgs e)
        {
            //sender's public key
            publicKeyPath = Environment.CurrentDirectory + @"\keys\sender\pub.bpg";
            //resiver's private key
            privateKeyPath = Environment.CurrentDirectory + @"\keys\reciver\secret.bpg";
            //pass phrase
            passPhrase = "ajar";

            PgpEncryptionKeys kes = new PgpEncryptionKeys(this.publicKeyPath, this.privateKeyPath, this.passPhrase);

            PgpDecrypt decFile = new PgpDecrypt(kes);

            using (var encStream = File.OpenRead(Environment.CurrentDirectory +  "\\tty.doc.pgp"))
            {
                decFile.VerifySignature(encStream, @"D:\Temp");
            }

        }

        private void button3_Click(object sender, RoutedEventArgs e)
        {
            filePath = Environment.CurrentDirectory + @"\exp\tty.doc";
            hashTypeName = "SHA1";
            
            //senders private key
            privateKeyPath = Environment.CurrentDirectory + @"\keys\sender\secret.bpg";
            //pass phrase
            passPhrase = "galileo";
            HybrydESD signatureOfFile = new HybrydESD();

            using (Stream   keyIn = File.OpenRead(privateKeyPath),
                            outPutStrm = File.Create(filePath + ".asc"))
            {
                
                signatureOfFile.SignFile(filePath,keyIn,outPutStrm,passPhrase.ToArray(),hashTypeName);
            }

        }

        private void button4_Click(object sender, RoutedEventArgs e)
        {
            
            filePath = Environment.CurrentDirectory + @"\exp\tty.doc.asc";
            FileInfo fInfo = new FileInfo(filePath);
            hashTypeName = "SHA1";
            //sender public key
            publicKeyPath = Environment.CurrentDirectory + @"\keys\sender\pub.bpg";
            //pass phrase
            passPhrase = "galileo";

            string str = fInfo.Name.Substring(0, fInfo.Name.Length-4);
            HybrydESD signatureOfFile = new HybrydESD();
            using(Stream signedFile = File.OpenRead(filePath),pubKeyIn = File.OpenRead(publicKeyPath))
            {
                signatureOfFile.VerifyFile(signedFile, pubKeyIn, str);
            }
            

        }
    }
}
