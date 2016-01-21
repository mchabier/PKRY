using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BramaPlatnosci
{
    public class Serwer
    {
        public Socket listener = null;
        public static System.Security.Cryptography.X509Certificates.X509Certificate serverCertificate = new X509Certificate2("CertyfikatSSLBramaPlatnosci.pfx", "instant");
        public void StartSerwer()
        {
            //Console.WriteLine("Sdsfsdf");
            IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, 1235); //punkt koncowy zdefiniowany
            listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                listener.Bind(localEndPoint); //dołacza do gniazda sieciowego punkt koncowy
                listener.Listen(200); //max ilosc obslugiwanych uzytkownikow
                while (true)
                {
                    Socket handler = listener.Accept(); //jak zglosi sie klient to przekzuje to do metody obsluz klienta

                    

                    Thread klientThread = new Thread(new ParameterizedThreadStart(ObsluzSprzedawce)); //definiuje watek do obslugi kolejnego klienta
                    klientThread.Start(handler); //startujac watek przekazuje parametr medody obsluzklienta i jest nim handler

                }
            }
            catch (Exception ex)
            {

            }

        }
        public string SHA1(string dohashowania)
        {
            SHA1CryptoServiceProvider SHA1 = new SHA1CryptoServiceProvider();
            SHA1.ComputeHash(ASCIIEncoding.ASCII.GetBytes(dohashowania));
            byte[] Re = SHA1.Hash;
            StringBuilder StringBuilder = new StringBuilder();
            foreach (byte b in Re)
            {
                StringBuilder.Append(b.ToString("x2"));
            }
            return StringBuilder.ToString();
        }

        public string RsaEncrypt(string clearText, AsymmetricKeyParameter prywatny)
        {
            AsymmetricKeyParameter key = prywatny;
            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);

            var encryptEngine = new Pkcs1Encoding(new RsaEngine());


            encryptEngine.Init(true, key);


            var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
            return encrypted;
        }
        public string RsaDecrypt(string base64Input, AsymmetricKeyParameter publiczny)
        {
            AsymmetricKeyParameter key = publiczny;
            var bytesToDecrypt = Convert.FromBase64String(base64Input);

            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            decryptEngine.Init(false, key);

            string decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            return decrypted;
        }


        public void ObsluzSprzedawce(object Sprzedawca)
        {
            while (true)
            {

                Socket nowySprzedawca = (Socket)Sprzedawca;
                NetworkStream stream = new NetworkStream(nowySprzedawca);
                SslStream sslStream = new SslStream(stream, false);
                try
                {
                    sslStream.AuthenticateAsServer(serverCertificate, false, System.Security.Authentication.SslProtocols.Tls, true);
                }
                catch (Exception ex)
                {
                    string sss = ex.ToString();
                    Program.brama.WpiszDoTextBoxa(ex.ToString());
                    
                }
                BinaryReader br = new BinaryReader(sslStream);
                BinaryWriter bw = new BinaryWriter(sslStream);

                //Wczytywanie klucza prywatnego Bramy Tylko dla klienta
                StreamReader readerKluczPrywatnyBramyTylkoDlaKlienta = new StreamReader("KluczPrywatnyBramyTylkoDlaKlienta.pem");
                PemReader pemReaderKluczPrywatnyBramyTylkoDlaKlienta = new PemReader(readerKluczPrywatnyBramyTylkoDlaKlienta);
                AsymmetricCipherKeyPair keyPairPriv = (AsymmetricCipherKeyPair)pemReaderKluczPrywatnyBramyTylkoDlaKlienta.ReadObject();
                AsymmetricKeyParameter kluczPrywatnyBramyTylkoDlaKlienta = keyPairPriv.Private;

                //Wczytywanie klucza prywatnego Bramy 
                StreamReader readerKluczPrywatnyBramy = new StreamReader("KluczPrywatnyBramyPlatnosci.pem");
                PemReader pemReaderKluczPrywatnyBramy = new PemReader(readerKluczPrywatnyBramy);
                AsymmetricCipherKeyPair keyPairPriv1 = (AsymmetricCipherKeyPair)pemReaderKluczPrywatnyBramy.ReadObject();
                AsymmetricKeyParameter kluczPrywatnyBramy = keyPairPriv1.Private;

                //Wczytywanie certyfikatu Bramy
                string sciezkaCertyfikatuBramyPlatnosci = "CertyfikatBramyPlatnosci.crt";
                X509Certificate2 certyfikatBramyPlatnosci = new X509Certificate2(sciezkaCertyfikatuBramyPlatnosci);

                byte[] certyfikatBramyPlatnosciDoWyslania = certyfikatBramyPlatnosci.GetRawCertData();
                int dlCBP = certyfikatBramyPlatnosciDoWyslania.Length;

                string odpowiedz = br.ReadString();
                if (odpowiedz == Protokol.AUTHORIZATION_REQ)
                {
                    Program.brama.WpiszDoTextBoxa("* Odebrałem wiadomość AUTHORIZATION_REQ od Sprzedawcy");
                    Program.brama.WpiszDoTextBoxa("");
                    string[] wiadomoscZapytanie = { br.ReadString(), br.ReadString(), br.ReadString(), br.ReadString() };
                    int dlCK = br.ReadInt32();
                    byte[] daneCertyfikatuKlienta = br.ReadBytes(dlCK);
                    int dlCS = br.ReadInt32();
                    byte[] daneCertyfikatuSprzedawcy = br.ReadBytes(dlCS);
                    int dlCKSTDB = br.ReadInt32();
                    byte[] daneCertyfikatuKluczasSprzedawcyTylkoDlaBramy = br.ReadBytes(dlCKSTDB);


                    X509Certificate2 certyfikatKlienta = new X509Certificate2();
                    certyfikatKlienta.Import(daneCertyfikatuKlienta);
                    X509Certificate2 certyfikatSprzedawcy = new X509Certificate2();
                    certyfikatSprzedawcy.Import(daneCertyfikatuSprzedawcy);
                    X509Certificate2 certyfikatKluczasSprzedawcyTylkoDlaBramy = new X509Certificate2();
                    certyfikatKluczasSprzedawcyTylkoDlaBramy.Import(daneCertyfikatuKluczasSprzedawcyTylkoDlaBramy);


                    //Uzyskanie klucza publicznego klienta z certyfikatu
                    X509CertificateParser certyfikatParser = new X509CertificateParser();
                    Org.BouncyCastle.X509.X509Certificate certyfikatBouncy = certyfikatParser.ReadCertificate(certyfikatKlienta.GetRawCertData());
                    AsymmetricKeyParameter kluczPublicznyKlienta = certyfikatBouncy.GetPublicKey();

                    //Uzyskanie klucza publicznego sprzedawcy z certyfikatu
                    X509CertificateParser certyfikatParser1 = new X509CertificateParser();
                    Org.BouncyCastle.X509.X509Certificate certyfikatBouncy1 = certyfikatParser1.ReadCertificate(certyfikatSprzedawcy.GetRawCertData());
                    AsymmetricKeyParameter kluczPublicznySprzedawcy = certyfikatBouncy1.GetPublicKey();

                    //Uzyskanie klucza publicznego klienta z certyfikatu
                    X509CertificateParser certyfikatParser2 = new X509CertificateParser();
                    Org.BouncyCastle.X509.X509Certificate certyfikatBouncy2 = certyfikatParser2.ReadCertificate(certyfikatKluczasSprzedawcyTylkoDlaBramy.GetRawCertData());
                    AsymmetricKeyParameter kluczSprzedawcyTylkoDlaBramy = certyfikatBouncy2.GetPublicKey();

                    string hashWiadomoscZapytanie = SHA1(wiadomoscZapytanie[0]);
                    string odszyfrowanaWiadomoscZapytanie = RsaDecrypt(wiadomoscZapytanie[1], kluczPublicznySprzedawcy);

                    if (hashWiadomoscZapytanie == odszyfrowanaWiadomoscZapytanie)
                    {
                        Program.brama.WpiszDoTextBoxa("* Wiadomość AUTHORIZATION_REQ poprawnie odkodowana");
                        Program.brama.WpiszDoTextBoxa("");
                    }
                    else
                    {
                        bw.Write(Protokol.BLAD);
                        Program.brama.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI!");
                        Program.brama.WpiszDoTextBoxa("");
                        break;
                    }

                    string[] wiadomoscPlatniczaDlaBramy = wiadomoscZapytanie[3].Split(' ');
                    string odszyfrowanaHash_OPI = RsaDecrypt(wiadomoscPlatniczaDlaBramy[2], kluczPrywatnyBramyTylkoDlaKlienta);
                    string PI = wiadomoscPlatniczaDlaBramy[0] + " " + wiadomoscPlatniczaDlaBramy[1];
                    string hash_PI = SHA1(PI);
                    string hash_OI = wiadomoscZapytanie[2];
                    string OPI = hash_OI + hash_PI;
                    string hash_OPI = SHA1(OPI);

                    if (hash_OPI == odszyfrowanaHash_OPI)
                    {
                        Program.brama.WpiszDoTextBoxa("* Wiadomość Płatnicza od Klienta przekazana przez Sprzedawcę poprawnie odkodowana");
                        Program.brama.WpiszDoTextBoxa("");
                    }
                    else
                    {
                        bw.Write(Protokol.BLAD);
                        Program.brama.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI!");
                        Program.brama.WpiszDoTextBoxa("");
                        break;
                    }

                    // odpowiedz na wiadomosc

                    string odpowiedzZapytanie = "Odpowiedz";
                    string hashOdpowiedzZapytanie = SHA1(odpowiedzZapytanie);
                    string zakodowanaHashWiadomoscOdpowiedz = RsaEncrypt(hashOdpowiedzZapytanie, kluczPrywatnyBramy);

                    // tu jest pobierany token od banku, to nie jest element protokolu SET
                    string TOKEN = "Token";
                    string hashToken = SHA1(TOKEN);

                    Program.brama.WpiszDoTextBoxa("* Wysyłam Wiadomość AUTHORIZATION_RES do Sprzedawcy");
                    Program.brama.WpiszDoTextBoxa("   - Jawna wiadomość ");
                    Program.brama.WpiszDoTextBoxa("   - Zakodowana wiadomość");
                    Program.brama.WpiszDoTextBoxa("   - Hash Tokena pobranego z Banku");
                    Program.brama.WpiszDoTextBoxa("   - Certyfikat Bramy Płatności");
                    Program.brama.WpiszDoTextBoxa("");
                    bw.Write(Protokol.AUTHORIZATION_RES);
                    bw.Write(odpowiedzZapytanie);
                    bw.Write(zakodowanaHashWiadomoscOdpowiedz);
                    bw.Write(hashToken);
                    bw.Write(dlCBP);
                    bw.Write(certyfikatBramyPlatnosciDoWyslania);


                }
                else
                {
                    bw.Write(Protokol.BLAD);
                    Program.brama.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI!");
                    Program.brama.WpiszDoTextBoxa("");
                    break;
                }
                odpowiedz = br.ReadString();


                if (odpowiedz == Protokol.PAYMENT_REQ)
                {
                    Program.brama.WpiszDoTextBoxa("* Odebrałem wiadomość PAYMENT_REQ od Sprzedawcy");
                    string[] wiadomoscZapytanieOPlatnosc = { br.ReadString(), br.ReadString(), br.ReadString(), };
                    int dlCS = br.ReadInt32();
                    byte[] daneCertyfikatuSprzedawcy1 = br.ReadBytes(dlCS);

                    X509Certificate2 certyfikatSprzedawcy1 = new X509Certificate2();
                    certyfikatSprzedawcy1.Import(daneCertyfikatuSprzedawcy1);

                    //Uzyskanie klucza publicznego sprzedawcy z certyfikatu
                    X509CertificateParser certyfikatParser12 = new X509CertificateParser();
                    Org.BouncyCastle.X509.X509Certificate certyfikatBouncy12 = certyfikatParser12.ReadCertificate(certyfikatSprzedawcy1.GetRawCertData());
                    AsymmetricKeyParameter kluczPublicznySprzedawcy1 = certyfikatBouncy12.GetPublicKey();

                    string hashZapytanieOPlatnosc = SHA1(wiadomoscZapytanieOPlatnosc[0]);
                    string odkodowanaHashZapytanieoPlatnosc = RsaDecrypt(wiadomoscZapytanieOPlatnosc[1], kluczPublicznySprzedawcy1);

                    if (odkodowanaHashZapytanieoPlatnosc == hashZapytanieOPlatnosc)
                    {
                        Program.brama.WpiszDoTextBoxa("* Wiadomość PAYMENT_REQ poprawnie odkodowana");
                        Program.brama.WpiszDoTextBoxa("");
                    }
                    else
                    {
                        bw.Write(Protokol.BLAD);
                        Program.brama.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI!");
                        Program.brama.WpiszDoTextBoxa("");
                        break;
                    }

                    string odpowiedzZapytanieOPlatnosc = "Odpowiedz zapytanie o platnosc";
                    string hashOdpowiedzZapytanieOPlatnosc = SHA1(odpowiedzZapytanieOPlatnosc);
                    string zakodowanaHashWiadomoscOdpowiedzZapytanieOPlatnosc = RsaEncrypt(hashOdpowiedzZapytanieOPlatnosc, kluczPrywatnyBramy);

                    Program.brama.WpiszDoTextBoxa("* Wysyłam Wiadomość PAYMENT_RES do Sprzedawcy");
                    Program.brama.WpiszDoTextBoxa("   - Jawna wiadomość ");
                    Program.brama.WpiszDoTextBoxa("   - Zakodowana wiadomość");
                    Program.brama.WpiszDoTextBoxa("   - Certyfikat Bramy Płatności");
                    Program.brama.WpiszDoTextBoxa("");
                    bw.Write(Protokol.PAYMENT_RES);
                    bw.Write(odpowiedzZapytanieOPlatnosc);
                    bw.Write(zakodowanaHashWiadomoscOdpowiedzZapytanieOPlatnosc);
                    bw.Write(dlCBP);
                    bw.Write(certyfikatBramyPlatnosciDoWyslania);

                }
                else
                {
                    bw.Write(Protokol.BLAD);
                    Program.brama.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI!");
                    Program.brama.WpiszDoTextBoxa("");
                    break;
                }
            }
            // koniec obsluz sprzedawce
        }
    }
   //koniec namepsacpe
}
