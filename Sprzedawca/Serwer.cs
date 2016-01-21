using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.X509;
using System.Windows.Forms;
using System.Net.Security;
using System.Collections;
/*zeby to zainstalowac tools->NuGet Package Manager ->Package Manager Console : Install-Package BouncyCastle-Ext */
namespace Sprzedawca
{
   
    public partial class Serwer : Form
    {

        public Socket listener = null;
        public static System.Security.Cryptography.X509Certificates.X509Certificate serverCertificate = new X509Certificate2("CertyfikatSSLSprzedawca.pfx", "instant");
        public void StartSerwer()
        {
            IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, 1234); //punkt koncowy zdefiniowany
            listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                listener.Bind(localEndPoint); //dołacza do gniazda sieciowego punkt koncowy
                listener.Listen(200); //max ilosc obslugiwanych uzytkownikow
                while (true)
                {
                    Socket handler = listener.Accept(); //jak zglosi sie klient to przekzuje to do metody obsluz klienta

                    Thread klientThread = new Thread(new ParameterizedThreadStart(ObsluzKlienta)); //definiuje watek do obslugi kolejnego klienta
                    klientThread.Start(handler); //startujac watek przekazuje parametr medody obsluzklienta i jest nim handler
                    
                }
            }
            catch (Exception ex)
            {
                Program.sprzedawca.WpiszDoTextBoxa(ex.ToString());
            }
            finally
            {
                listener.Close();
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

        private static Hashtable certificateErrors = new Hashtable();

        
        public static bool ValidateServerCertificate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            return true; //ufaj kazdemu nawet jak nie podpisany
        }

        public void ObsluzKlienta(object Klient)
        {
            while (true)
            {
                Socket nowyKlient = (Socket)Klient;
                NetworkStream stream = new NetworkStream(nowyKlient);
                SslStream sslStream = new SslStream(stream, false);
                sslStream.AuthenticateAsServer(serverCertificate, false, System.Security.Authentication.SslProtocols.Tls, true);
                BinaryReader br = new BinaryReader(sslStream);
                BinaryWriter bw = new BinaryWriter(sslStream);
               
              

                //Wczytywanie klucza prywatnego Sprzedającego
                StreamReader readerKluczPrywatny = new StreamReader("KluczPrywatnySprzedawcy.pem");
                PemReader pemReaderKluczPrywatny = new PemReader(readerKluczPrywatny);
                AsymmetricCipherKeyPair keyPairPriv = (AsymmetricCipherKeyPair)pemReaderKluczPrywatny.ReadObject();
                AsymmetricKeyParameter kluczPrywatnySprzedawcy = keyPairPriv.Private;

                //Wczytywanie Klucza Publicznego Sprzedającego
                StreamReader readerKluczPubliczny = new StreamReader("KluczPublicznySprzedawcy.pem");
                PemReader pemReaderKluczPubliczny = new PemReader(readerKluczPubliczny);
                AsymmetricKeyParameter kluczPublicznySprzedawcy = (AsymmetricKeyParameter)pemReaderKluczPubliczny.ReadObject();

                //Wczytywanie certyfikatu Sprzedawcy
                string sciezkaCertyfikatuSprzedawcy = "CertyfikatSprzedawcy.crt";
                X509Certificate2 certyfikatSprzedawcy = new X509Certificate2(sciezkaCertyfikatuSprzedawcy);

                //Wczytywanie certyfikatu klucza Sprzedawcy Tylko Dla Bramy
                string sciezkaCertyfikatuKluczaSprzedawcyTylkoDlaBramy = "CertyfikatSprzedawcy.crt";
                X509Certificate2 certyfikatKluczaSprzedawcyTylkoDlaBramy = new X509Certificate2(sciezkaCertyfikatuKluczaSprzedawcyTylkoDlaBramy);

                //Wczytywanie certyfikatu Bramy Platnosci
                string sciezkaCertyfikatuBramy = "CertyfikatSprzedawcy.crt";
                X509Certificate2 certyfikatBramy = new X509Certificate2(sciezkaCertyfikatuBramy);

                byte[] certyfikatSprzedawcyDoWyslania = certyfikatSprzedawcy.GetRawCertData();
                byte[] certyfikatBramyDoWyslania = certyfikatSprzedawcy.GetRawCertData();
                byte[] certyfikatKluczaSprzedawcyTylkoDlaBramyDoWyslania = certyfikatKluczaSprzedawcyTylkoDlaBramy.GetRawCertData();
                int dlCKSTDB = certyfikatKluczaSprzedawcyTylkoDlaBramyDoWyslania.Length;
                int dlCS = certyfikatSprzedawcyDoWyslania.Length;
                int dlCB = certyfikatBramyDoWyslania.Length;


                string odebrane = br.ReadString();

                if (odebrane == Protokol.PURCHASE_INIT)
                {
                    Program.sprzedawca.WpiszDoTextBoxa("* Odebrałem wiadomość PURCHASE_INIT od Klienta");
                    Program.sprzedawca.WpiszDoTextBoxa("");
                    string[] odebranaPierwszaWiadomosc = { br.ReadString(), br.ReadString() };

                    string odpowiedzPierwszaWiadomosc = "Przyjalem zgloszenie";
                    string hashOdpowiedzPierwszaWiadomosc = SHA1(odpowiedzPierwszaWiadomosc);
                    string zakodowanaOdpowiedzPierwszaWiadomosc = RsaEncrypt(hashOdpowiedzPierwszaWiadomosc, kluczPrywatnySprzedawcy);


                    Program.sprzedawca.WpiszDoTextBoxa("* Wysyłam wiadomość PURCHASE_INIT_RES do Klienta");
                    Program.sprzedawca.WpiszDoTextBoxa("  - Odpowiedź jawna");
                    Program.sprzedawca.WpiszDoTextBoxa("  - Zakodowany hash odpowiedzi jawnej");
                    Program.sprzedawca.WpiszDoTextBoxa("  - Certyfikat Sprzedawcy");
                    Program.sprzedawca.WpiszDoTextBoxa("  - Certyfikat Bramy Płatnosci");
                    Program.sprzedawca.WpiszDoTextBoxa("");

                    bw.Write(Protokol.PURCHASE_INIT_RES);
                    bw.Write(odpowiedzPierwszaWiadomosc);
                    bw.Write(zakodowanaOdpowiedzPierwszaWiadomosc);
                    bw.Write(dlCS);
                    bw.Write(certyfikatSprzedawcyDoWyslania);
                    bw.Write(dlCB);
                    bw.Write(certyfikatBramyDoWyslania);


                    odebrane = br.ReadString();
                    if (odebrane == Protokol.PURCHASE_REQ)
                    {
                        Program.sprzedawca.WpiszDoTextBoxa("* Odebrałem wiadomość PURCHASE_REQ od Klienta");
                        Program.sprzedawca.WpiszDoTextBoxa("");
                        string[] odebranaDrugaWiadomosc = { br.ReadString(), br.ReadString(), br.ReadString(), br.ReadString() };
                        int dlCK = br.ReadInt32();
                        byte[] daneCertyfikatuKlienta = br.ReadBytes(dlCK);

                        X509Certificate2 certyfikatKlienta = new X509Certificate2();
                        certyfikatKlienta.Import(daneCertyfikatuKlienta);

                        //Uzyskanie klucza publicznego klienta z certyfikatu
                        X509CertificateParser certyfikatParser = new X509CertificateParser();
                        Org.BouncyCastle.X509.X509Certificate certyfikatBouncy = certyfikatParser.ReadCertificate(certyfikatKlienta.GetRawCertData());
                        AsymmetricKeyParameter kluczPublicznyKlienta = certyfikatBouncy.GetPublicKey();


                        string hashDrugaWiadomosc_OI = SHA1(odebranaDrugaWiadomosc[2]);
                        string drugaWiadomosc_OPI = hashDrugaWiadomosc_OI + odebranaDrugaWiadomosc[1];
                        string hashDrugaWiadomosc_OPI = SHA1(drugaWiadomosc_OPI);

                        string odkodowanaHashDrugaWiadomosc_OPI = RsaDecrypt(odebranaDrugaWiadomosc[3], kluczPublicznyKlienta);
                        if (hashDrugaWiadomosc_OPI == odkodowanaHashDrugaWiadomosc_OPI)
                        {
                            Program.sprzedawca.WpiszDoTextBoxa("* Wiadomość PURCHASE_REQ poprawnie odkodowana");
                            Program.sprzedawca.WpiszDoTextBoxa("");

                        }
                        else
                        {
                            bw.Write(Protokol.BLAD);
                            Program.sprzedawca.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI!");
                            Program.sprzedawca.WpiszDoTextBoxa("");
                            break;
                        }


                        //tutaj tworzy sie połaczenie do bramy platnosci i potwierdza wszytko w bramie

                        try
                        {
                            Socket KlientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                            try
                            {
                                KlientSocket.Connect("127.0.0.1", 1235);
                                NetworkStream stream1 = new NetworkStream(KlientSocket);
                                SslStream sslStream1 = new SslStream(stream1, false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                                sslStream1.AuthenticateAsClient("InstantMessengerServer");
                                BinaryWriter bw1 = new BinaryWriter(sslStream1);
                                BinaryReader br1 = new BinaryReader(sslStream1);

                                // Tu jest cała komunikacja z bramą zeby potwierdzic Klienta i rozpoczac proces poboru opłaty


                                string identyfikatorTransakcji = "1111";
                                string wiadomoscZapytanie = "Proszę o autoryzację" + " " + identyfikatorTransakcji;
                                string hashWiadomoscZapytanie = SHA1(wiadomoscZapytanie);
                                string podpisanyHashWiadomoscZapytanie = RsaEncrypt(hashWiadomoscZapytanie, kluczPrywatnySprzedawcy);

                                Program.sprzedawca.WpiszDoTextBoxa("* Wysyłam wiadomość AUTHORIZATION_REQ do Bramy Płatności");
                                Program.sprzedawca.WpiszDoTextBoxa("  - Jawna wiadomość");
                                Program.sprzedawca.WpiszDoTextBoxa("  - Zakodowana wiadomość");
                                Program.sprzedawca.WpiszDoTextBoxa("  - Hash wiadomości dotyczącej zamówienia");
                                Program.sprzedawca.WpiszDoTextBoxa("  - Zakodowana wiadomość płatnicza dla bramy");
                                Program.sprzedawca.WpiszDoTextBoxa("  - Certyfikat Klienta");
                                Program.sprzedawca.WpiszDoTextBoxa("  - Certyfikat Sprzedawcy");
                                Program.sprzedawca.WpiszDoTextBoxa("");
                                bw1.Write(Protokol.AUTHORIZATION_REQ);
                                bw1.Write(wiadomoscZapytanie);
                                bw1.Write(podpisanyHashWiadomoscZapytanie);
                                bw1.Write(hashDrugaWiadomosc_OI);
                                bw1.Write(odebranaDrugaWiadomosc[0]);
                                bw1.Write(dlCK);
                                bw1.Write(daneCertyfikatuKlienta);
                                bw1.Write(dlCS);
                                bw1.Write(certyfikatSprzedawcyDoWyslania);
                                bw1.Write(dlCKSTDB);
                                bw1.Write(certyfikatKluczaSprzedawcyTylkoDlaBramyDoWyslania);


                                //Odbior odpowiedzi od bramy
                                string odebrane1 = br1.ReadString();
                                string[] zapytanieOdpowiedz1 = null;
                                if (odebrane1 == Protokol.AUTHORIZATION_RES)
                                {
                                    Program.sprzedawca.WpiszDoTextBoxa("* Odebrałem wiadomość AUTHORIZATION_RES od Bramy Płatności");
                                    Program.sprzedawca.WpiszDoTextBoxa("");
                                    string[] zapytanieOdpowiedz = { br1.ReadString(), br1.ReadString(), br1.ReadString() };

                                    int dlCBP = br1.ReadInt32();
                                    byte[] daneCertyfikatuBramyPlatnosci = br1.ReadBytes(dlCBP);

                                    string hashZapytanieOdpowiedz = SHA1(zapytanieOdpowiedz[0]);

                                    X509Certificate2 certyfikatBramyPlatnosci = new X509Certificate2();
                                    certyfikatBramyPlatnosci.Import(daneCertyfikatuBramyPlatnosci);

                                    //Uzyskanie klucza publicznego bramy platnosci z certyfikatu
                                    X509CertificateParser certyfikatbramyParser = new X509CertificateParser();
                                    Org.BouncyCastle.X509.X509Certificate certyfikatbramyBouncy = certyfikatbramyParser.ReadCertificate(certyfikatBramyPlatnosci.GetRawCertData());
                                    AsymmetricKeyParameter kluczPublicznyBramyPlatnosci = certyfikatbramyBouncy.GetPublicKey();

                                    string odszyfrowanahashZapytanieOdpowiedz = RsaDecrypt(zapytanieOdpowiedz[1], kluczPublicznyBramyPlatnosci);

                                    if (odszyfrowanahashZapytanieOdpowiedz == hashZapytanieOdpowiedz)
                                    {
                                        Program.sprzedawca.WpiszDoTextBoxa("* Wiadomość AUTHORIZATION_RES poprawnie odkodowana");
                                        Program.sprzedawca.WpiszDoTextBoxa("");
                                    }
                                    else
                                    {
                                        bw.Write(Protokol.BLAD);
                                        bw1.Write(Protokol.BLAD);
                                        Program.sprzedawca.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI!");
                                        Program.sprzedawca.WpiszDoTextBoxa("");
                                        break;
                                    }

                                    zapytanieOdpowiedz1 = zapytanieOdpowiedz;
                                }
                                else
                                {
                                    bw.Write(Protokol.BLAD);
                                    bw1.Write(Protokol.BLAD);
                                    Program.sprzedawca.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI!");
                                    Program.sprzedawca.WpiszDoTextBoxa("");
                                    break;
                                }


                                //Tu pobor opłaty

                                string wiadomoscZapytanieOPlatnosc = "Proszę o rozpoczecie poboru platnosci" + " " + identyfikatorTransakcji;
                                string hashWiadomoscZapytanieOPlatnosc = SHA1(wiadomoscZapytanieOPlatnosc);
                                string podpisanyHashWiadomoscZapytanieOPlatnosc = RsaEncrypt(hashWiadomoscZapytanieOPlatnosc, kluczPrywatnySprzedawcy);

                                Program.sprzedawca.WpiszDoTextBoxa("* Wysyłam wiadomość PAYMENT_REQ do Bramy Płatności");
                                Program.sprzedawca.WpiszDoTextBoxa("  - Jawna wiadomość");
                                Program.sprzedawca.WpiszDoTextBoxa("  - Zakodowana wiadomość");
                                Program.sprzedawca.WpiszDoTextBoxa("  - Token");
                                Program.sprzedawca.WpiszDoTextBoxa("  - Certyfikat Sprzedawcy");
                                Program.sprzedawca.WpiszDoTextBoxa("");

                                bw1.Write(Protokol.PAYMENT_REQ);
                                bw1.Write(wiadomoscZapytanieOPlatnosc);
                                bw1.Write(podpisanyHashWiadomoscZapytanieOPlatnosc);
                                bw1.Write(zapytanieOdpowiedz1[2]);
                                bw1.Write(dlCS);
                                bw1.Write(certyfikatSprzedawcyDoWyslania);

                                string odp = br1.ReadString();
                                if (odp == Protokol.PAYMENT_RES)
                                {
                                    Program.sprzedawca.WpiszDoTextBoxa("* Odebrałem wiadomość PAYMENT_RES od Bramy Płatności");
                                    Program.sprzedawca.WpiszDoTextBoxa("");
                                    string[] odpowiedzOplatnosc = { br1.ReadString(), br1.ReadString() };
                                    int dlCBP = br1.ReadInt32();
                                    byte[] daneCertyfikatuBramyPlatnosci = br1.ReadBytes(dlCBP);

                                    X509Certificate2 certyfikatBramyPlatnosci = new X509Certificate2();
                                    certyfikatBramyPlatnosci.Import(daneCertyfikatuBramyPlatnosci);

                                    //Uzyskanie klucza publicznego bramy platnosci z certyfikatu
                                    X509CertificateParser certyfikatbramyParser = new X509CertificateParser();
                                    Org.BouncyCastle.X509.X509Certificate certyfikatbramyBouncy = certyfikatbramyParser.ReadCertificate(certyfikatBramyPlatnosci.GetRawCertData());
                                    AsymmetricKeyParameter kluczPublicznyBramyPlatnosci = certyfikatbramyBouncy.GetPublicKey();

                                    string hashOdpowiedzOplatnosc = SHA1(odpowiedzOplatnosc[0]);
                                    string odkodowanehashOdpowiedzOPlatnosc = RsaDecrypt(odpowiedzOplatnosc[1], kluczPublicznyBramyPlatnosci);

                                    if (hashOdpowiedzOplatnosc == odkodowanehashOdpowiedzOPlatnosc)
                                    {
                                        Program.sprzedawca.WpiszDoTextBoxa("* Wiadomość PAYMENT_RES poprawnie odkodowana");
                                        Program.sprzedawca.WpiszDoTextBoxa("");
                                    }
                                    else
                                    {
                                        bw.Write(Protokol.BLAD);
                                        bw1.Write(Protokol.BLAD);
                                        Program.sprzedawca.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI!");
                                        Program.sprzedawca.WpiszDoTextBoxa("");
                                        break;
                                    }

                                }
                                else
                                {
                                    bw.Write(Protokol.BLAD);
                                    bw1.Write(Protokol.BLAD);
                                    Program.sprzedawca.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI!");
                                    Program.sprzedawca.WpiszDoTextBoxa("");
                                    break;
                                }



                                //KlientSocket.Shutdown(SocketShutdown.Both);
                                //KlientSocket.Close();
                            }
                            catch (ArgumentNullException ane)
                            {
                                Program.sprzedawca.WpiszDoTextBoxa(ane.ToString());
                            }
                            catch (SocketException se)
                            {
                                Program.sprzedawca.WpiszDoTextBoxa(se.ToString());
                            }
                            catch (Exception e)
                            {
                                Program.sprzedawca.WpiszDoTextBoxa(e.ToString());
                            }
                        }
                        catch (Exception e)
                        {
                            Program.sprzedawca.WpiszDoTextBoxa(e.ToString());
                        }

                        //odpisuje klientowi ze wszytko ok

                        string odpowiedzDrugaWiadomosc = "Wszytko OK";
                        string hashOdpowiedzDrugaWiadomosc = SHA1(odpowiedzDrugaWiadomosc);
                        string zakodowanaOdpowiedzDrugaWiadomosc = RsaEncrypt(hashOdpowiedzDrugaWiadomosc, kluczPrywatnySprzedawcy);

                        Program.sprzedawca.WpiszDoTextBoxa("* Wysyłam wiadomość PURCHASE_REQ_RES do Klienta");
                        Program.sprzedawca.WpiszDoTextBoxa("  - Jawna wiadomość");
                        Program.sprzedawca.WpiszDoTextBoxa("  - Zakodowana wiadomość");
                        Program.sprzedawca.WpiszDoTextBoxa("");
                        bw.Write(Protokol.PURCHASE_REQ_RES);
                        bw.Write(odpowiedzDrugaWiadomosc);
                        bw.Write(zakodowanaOdpowiedzDrugaWiadomosc);

                    }
                    else
                    {
                        bw.Write(Protokol.BLAD);
                        Program.sprzedawca.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI");
                        Program.sprzedawca.WpiszDoTextBoxa("");
                        break;

                    }

                    //koniec if
                }
                else
                {
                    bw.Write(Protokol.BLAD);
                    Program.sprzedawca.WpiszDoTextBoxa("* BŁĄD W KOMUNIKACJI");
                    Program.sprzedawca.WpiszDoTextBoxa("");
                    break;
                }
                //koniec obsluz klienta
            }
        }
      //Koniec Class Serwer   
    }
    //Kniec namespace Sprzedawca
}









