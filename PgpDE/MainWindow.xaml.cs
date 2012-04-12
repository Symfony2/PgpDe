﻿using System;
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
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string publicKeyPath;
        private string privateKeyPath;
        private string passPhrase;
        public MainWindow()
        {
            InitializeComponent();
            publicKeyPath = @"C:\Users\Symfony\Documents\keys\Yan\pub.bpg";
            privateKeyPath = @"C:\Users\Symfony\Documents\keys\Almaz\secret.bpg";
            passPhrase = "root";
        }

        private void button1_Click(object sender, RoutedEventArgs e)
        {

            PgpEncryptionKeys kes = new PgpEncryptionKeys(this.publicKeyPath, this.privateKeyPath, this.passPhrase);
            PgpEncrypt ecnFile = new PgpEncrypt(kes);
            FileInfo fileInfo = new FileInfo(@"D:\Temp\Шаляпин.doc");
            
            //FileInfo fileInfo = new FileInfo(@"D:\Temp\11122.xlsx");
            //using (Stream outStrm = File.Create(@"C:\Users\Symfony\" + fileInfo.Name + ".enc"))
            using (Stream outStrm = File.Create(@"C:\Users\Symfony\" + fileInfo.Name + ".enc"))
            {                
                ecnFile.EncryptAndSign(outStrm, fileInfo);                
            }
            
        }

        private void button2_Click(object sender, RoutedEventArgs e)
        {
            PgpEncryptionKeys kes = new PgpEncryptionKeys(@"C:\Users\Symfony\Documents\keys\Almaz\pub.bpg",
                                                          @"C:\Users\Symfony\Documents\keys\Yan\secret.bpg", 
                                                          "acer");
            PgpDecrypt decFile = new PgpDecrypt(kes);
            //StreamReader strRd = new StreamReader(File.OpenRead(@"C:\Users\Symfony\Шаляпин.doc.enc"), Encoding.ASCII);
            using (var encStream = File.OpenRead(@"C:\Users\Symfony\Шаляпин.doc.enc"))            
            {
                decFile.VerifySignature(encStream, @"D:\Temp");
                //MessageBox.Show(decFile.Decrypt(encStream, @"D:\Temp"));
            }
            

        }
    }
}